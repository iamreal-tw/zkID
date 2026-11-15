/**
 * Structure-derived modulus offset in CertChainRSA256.
 *
 * The circuit continues the DER walk past Validity and the subject Name to
 * the SubjectPublicKeyInfo, so the offset of the user modulus is no longer a
 * prover input (audit v3, Finding 1).
 */
import { WitnessTester } from "circomkit";
import assert from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { circomkit } from "../common";
import {
  buildTbs,
  chainInputs,
  makeTestCa,
  makeUserSpki,
  name,
  opaqueExtension,
  spkiOfModulusBytes,
  type TbsOptions,
  type TestCa,
} from "../common/testCert";

const NOW = 261114155959n;

/** Subject Name whose content is exactly `contentLength` bytes. */
function subjectOfLength(contentLength: number): Buffer {
  // C (13) + CN (11 + 9) = 33 fixed; an OU of n bytes costs 11 + n.
  const ouLengths: number[] = [];
  let left = contentLength - 33;
  while (left > 0) {
    let cost = Math.min(left, 71);
    // Leave room for one more OU (at least 12 bytes) if anything remains.
    if (left - cost > 0 && left - cost < 12) cost = left - 12;
    ouLengths.push(cost - 11);
    left -= cost;
  }
  const subject = name("Test User", ouLengths);
  const headerLength = contentLength < 128 ? 2 : contentLength < 256 ? 3 : 4;
  assert.strictEqual(subject.length, headerLength + contentLength);
  return subject;
}

describe("CertChainRSA256 structure-derived modulus offset", function () {
  let circuit: WitnessTester;
  let ca: TestCa;
  let spki: Buffer;

  before(async function () {
    this.timeout(900_000);
    ca = makeTestCa();
    spki = makeUserSpki();
    circuit = await circomkit.WitnessTester("certChainModulusOffset", {
      file: "certChain",
      template: "CertChainRSA256",
      params: [1536, 121, 17, 2048, 17, 2048, 128, 20],
    });
  });

  function inputs(opts: Partial<TbsOptions>) {
    return chainInputs(ca, buildTbs({ spki, ...opts }), NOW);
  }

  async function accepts(input: Record<string, any>) {
    const witness = await circuit.calculateWitness(input as any);
    await circuit.expectConstraintPass(witness);
    return witness;
  }

  describe("accepts", function () {
    for (const length of [127, 128, 255]) {
      it(`a subject Name of ${length} content bytes`, async function () {
        await accepts(inputs({ subject: subjectOfLength(length) }));
      });
    }
  });

  describe("rejects", function () {
    it("a subject Name of 256 content bytes (two-byte long-form length)", async function () {
      await circuit.expectFail(inputs({ subject: subjectOfLength(256) }) as any);
    });

    it("a 4096-bit RSA subject key", async function () {
      await circuit.expectFail(inputs({ spki: makeUserSpki(4096) }) as any);
    });
  });

  // The pinned `02 82 01 01 00` fixes the encoded length of the modulus, not
  // the size of the key: only the top bit of the first modulus byte does.
  describe("requires the subject key to be exactly 2048 bits", function () {
    /** The 256 modulus bytes of a 2048-bit key, with the first byte replaced. */
    function withFirstByte(first: number): Buffer {
      const m = Buffer.from(spki.subarray(33, 33 + 256));
      m[0] = first;
      return spkiOfModulusBytes(m);
    }

    it("the layout helper rebuilds the SPKI Node exports", function () {
      assert.ok(spkiOfModulusBytes(spki.subarray(33, 33 + 256)).equals(spki));
    });

    it("accepts a first modulus byte of 0x80", async function () {
      await accepts(inputs({ spki: withFirstByte(0x80) }));
    });

    it("rejects a first modulus byte of 0x7f", async function () {
      await circuit.expectFail(inputs({ spki: withFirstByte(0x7f) }) as any);
    });

    it("rejects a 2047-bit key written into 256 bytes", async function () {
      const { publicKey } = generateKeyPairSync("rsa", {
        modulusLength: 2047,
        publicExponent: 65537,
      });
      const n = Buffer.from(publicKey.export({ format: "jwk" }).n as string, "base64url");
      assert.strictEqual(n.length, 256);
      assert.ok(n[0] < 0x80);
      await circuit.expectFail(inputs({ spki: spkiOfModulusBytes(n) }) as any);
    });

    it("rejects a 1024-bit key written with leading zeros", async function () {
      const { publicKey } = generateKeyPairSync("rsa", {
        modulusLength: 1024,
        publicExponent: 65537,
      });
      const n = Buffer.from(publicKey.export({ format: "jwk" }).n as string, "base64url");
      const padded = Buffer.concat([Buffer.alloc(256 - n.length), n]);
      await circuit.expectFail(inputs({ spki: spkiOfModulusBytes(padded) }) as any);
    });
  });

  it("ignores a decoy modulus prefix elsewhere in the TBS", async function () {
    // An extension whose value starts with the same DER prefix as a 2048-bit
    // modulus INTEGER, followed by 256 arbitrary bytes. A prover-supplied
    // offset could have pointed here; the derived offset cannot.
    const decoy = Buffer.concat([
      Buffer.from("0282010100", "hex"),
      Buffer.alloc(256, 0xab),
    ]);
    const plain = inputs({});
    const withDecoy = inputs({ extraExtensions: [opaqueExtension(decoy)] });

    const prefix = Buffer.from("0282010100", "hex");
    const tbs = Buffer.from(
      (withDecoy.issuerTbs as bigint[]).map((b) => Number(b))
    ).subarray(0, Number(withDecoy.actualIssuerTbsLength));
    const first = tbs.indexOf(prefix);
    assert.notStrictEqual(tbs.indexOf(prefix, first + 1), -1, "decoy prefix missing");

    // pkCommit is the circuit's only output: witness index 1.
    const plainCommit = (await accepts(plain))[1];
    const decoyCommit = (await accepts(withDecoy))[1];
    assert.strictEqual(decoyCommit, plainCommit);
  });
});
