/**
 * Primary-card check in CertChainRSA256.
 *
 * MOICA marks secondary-card and mobile certificates with a cardHolderRank
 * attribute in subjectDirectoryAttributes; a primary card's certificate has
 * none. Each of those certificates has its own key, so without this check one
 * person holding several certificates gets several nullifiers per app. The
 * same extension states whether the holder is a citizen or an alien resident;
 * only citizens are accepted.
 */
import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import {
  buildTbs,
  cardHolderRank,
  CERT_POLICIES,
  chainInputs,
  makeTestCa,
  makeUserSpki,
  opaqueExtension,
  SUBJECT_DIR_ATTRS,
  subjectDirectoryAttributes,
  type TbsOptions,
  type TestCa,
} from "../common/testCert";

const NOW = 261114155959n;

describe("CertChainRSA256 primary card", function () {
  let circuit: WitnessTester;
  let ca: TestCa;
  let spki: Buffer;

  before(async function () {
    this.timeout(900_000);
    ca = makeTestCa();
    spki = makeUserSpki();
    circuit = await circomkit.WitnessTester("certChainPrimaryCard", {
      file: "certChain",
      template: "CertChainRSA256",
      params: [1536, 121, 17, 2048, 17, 2048, 128, 20],
    });
  });

  function inputs(opts: Partial<TbsOptions>) {
    return chainInputs(ca, buildTbs({ spki, ...opts }), NOW);
  }

  describe("accepts", function () {
    it("a primary-card certificate", async function () {
      const witness = await circuit.calculateWitness(inputs({}) as any);
      await circuit.expectConstraintPass(witness);
    });

    it("any tailOfPersonalID value", async function () {
      const witness = await circuit.calculateWitness(
        inputs({
          holderExtensions: [CERT_POLICIES, subjectDirectoryAttributes("9870")],
        }) as any
      );
      await circuit.expectConstraintPass(witness);
    });
  });

  describe("rejects", function () {
    it("an alien-resident primary-card certificate", async function () {
      // subjectType 2.16.886.1.100.3.1.9; otherwise the same layout.
      await circuit.expectFail(
        inputs({
          holderExtensions: [
            CERT_POLICIES,
            subjectDirectoryAttributes("5678", [], false, 0x09),
          ],
        }) as any
      );
    });

    it("another subjectType", async function () {
      // 2.16.886.1.100.3.1.2 is not a natural person.
      await circuit.expectFail(
        inputs({
          holderExtensions: [
            CERT_POLICIES,
            subjectDirectoryAttributes("1234", [], false, 0x02),
          ],
        }) as any
      );
    });

    it("an alien-resident certificate with cardHolderRank = mobile", async function () {
      await circuit.expectFail(
        inputs({
          holderExtensions: [
            CERT_POLICIES,
            subjectDirectoryAttributes("5678", [cardHolderRank("mobile")], false, 0x09),
          ],
        }) as any
      );
    });

    for (const rank of ["mobile", "secondary"]) {
      it(`a certificate with cardHolderRank = ${rank}`, async function () {
        await circuit.expectFail(
          inputs({
            holderExtensions: [
              CERT_POLICIES,
              subjectDirectoryAttributes("1234", [cardHolderRank(rank)]),
            ],
          }) as any
        );
      });
    }

    it("cardHolderRank placed before the other attributes", async function () {
      const sda = subjectDirectoryAttributes("1234", [cardHolderRank("mobile")]);
      // Move the rank attribute to the front of the SEQUENCE OF Attribute.
      const rank = cardHolderRank("mobile");
      const body = sda.subarray(11);
      const reordered = Buffer.concat([
        sda.subarray(0, 11),
        rank,
        body.subarray(0, body.length - rank.length),
      ]);
      await circuit.expectFail(
        inputs({ holderExtensions: [CERT_POLICIES, reordered] }) as any
      );
    });

    it("the two attributes in the other order", async function () {
      await circuit.expectFail(
        inputs({
          holderExtensions: [
            CERT_POLICIES,
            subjectDirectoryAttributes("1234", [], true),
          ],
        }) as any
      );
    });

    it("a different certificate policy", async function () {
      // 2.16.886.101.0.3.2 instead of ...3.3.
      const other = Buffer.from(CERT_POLICIES);
      other[other.length - 1] = 0x02;
      await circuit.expectFail(
        inputs({ holderExtensions: [other, SUBJECT_DIR_ATTRS] }) as any
      );
    });

    it("no subjectDirectoryAttributes", async function () {
      await circuit.expectFail(
        inputs({ holderExtensions: [CERT_POLICIES] }) as any
      );
    });

    it("subjectDirectoryAttributes before certificatePolicies", async function () {
      await circuit.expectFail(
        inputs({ holderExtensions: [SUBJECT_DIR_ATTRS, CERT_POLICIES] }) as any
      );
    });

    it("an unrelated extension between keyUsage and certificatePolicies", async function () {
      await circuit.expectFail(
        inputs({
          holderExtensions: [
            opaqueExtension(Buffer.alloc(4, 0xdd)),
            CERT_POLICIES,
            SUBJECT_DIR_ATTRS,
          ],
        }) as any
      );
    });

    it("a TBS truncated inside subjectDirectoryAttributes", async function () {
      const full = buildTbs({ spki });
      const cut = full.indexOf(SUBJECT_DIR_ATTRS) + SUBJECT_DIR_ATTRS.length - 2;
      const truncated = Buffer.from(full.subarray(0, cut));
      truncated.writeUInt16BE(cut - 4, 2);
      await circuit.expectFail(chainInputs(ca, truncated, NOW) as any);
    });
  });
});
