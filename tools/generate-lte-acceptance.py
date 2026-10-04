"""Generate artificial LTE analyzer fixtures with an independent UPER encoder."""

import argparse
import copy
import json
from pathlib import Path

import asn1tools


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("specs", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    codec = asn1tools.compile_files([str(p) for p in sorted(args.specs.glob("*.asn"))], codec="uper")
    cases = []

    def rrc(type_name, channel, value):
        encoded = codec.encode(type_name, value)
        assert codec.encode(type_name, codec.decode(type_name, encoded)) == encoded
        return {"channel": channel, "hex": encoded.hex()}

    def nas(hex_data):
        return {"channel": 0, "hex": hex_data}

    def case(name, target, expected, packets):
        cases.append({"name": name, "target": target, "expected": expected, "packets": packets})

    def downlink(name, value):
        return rrc("DL-DCCH-Message", 9, {"message": ("c1", (name, value))})

    def security(cipher):
        return downlink("securityModeCommand", {
            "rrc-TransactionIdentifier": 0,
            "criticalExtensions": ("c1", ("securityModeCommand-r8", {
                "securityConfigSMC": {"securityAlgorithmConfig": {
                    "cipheringAlgorithm": cipher, "integrityProtAlgorithm": "eia2",
                }},
            })),
        })

    def release(carrier):
        return downlink("rrcConnectionRelease", {
            "rrc-TransactionIdentifier": 0,
            "criticalExtensions": ("c1", ("rrcConnectionRelease-r8", {
                "releaseCause": "other", "redirectedCarrierInfo": carrier,
            })),
        })

    geran = {"startingARFCN": 1, "bandIndicator": "dcs1800",
             "followingARFCNs": ("explicitListOfARFCNs", [])}
    case("RRC EEA0 is High", 3, "High", [security("eea0")])
    case("RRC EEA2 is not a null-cipher alert", 3, None, [security("eea2")])
    case("GERAN redirection is High", 1, "High", [release(("geran", geran))])
    case("LTE redirection is informational", 1, "Informational", [release(("eutra", 1))])
    case("Known NR redirection CHOICE extension decodes, not GERAN", 1, "Informational", [
        release(("nr-r15", {"carrierFreq-r15": 1, "subcarrierSpacingSSB-r15": "kHz15"}))
    ])
    case("NAS EEA0 is High", 4, "High", [nas("075d000002e0e0")])
    case("NAS EEA2 is not a null-cipher alert", 4, None, [nas("075d200002e0e0")])
    identity = nas("075501")
    authentication = nas("07530401020304")
    case("Identity after authentication is High", 0, "High", [authentication, identity])
    case("Identity before authentication is not suspicious", 0, None, [identity, authentication])
    case("Identity after rejection is High", 0, "High", [nas("074403"), identity])
    case("Identity request emits diagnostic information", 7, "Informational", [identity])
    case("Authentication response is not an exposure diagnostic", 7, None, [authentication])

    # All identifiers and network values below are artificial test values.
    sib1 = {
        "cellAccessRelatedInfo": {
            "plmn-IdentityList": [{
                "plmn-Identity": {"mcc": [0, 0, 1], "mnc": [0, 1]},
                "cellReservedForOperatorUse": "notReserved",
            }],
            "trackingAreaCode": (bytes(2), 16), "cellIdentity": (bytes(4), 28),
            "cellBarred": "notBarred", "intraFreqReselection": "allowed",
            "csg-Indication": False,
        },
        "cellSelectionInfo": {"q-RxLevMin": -60},
        "freqBandIndicator": 1,
        "schedulingInfoList": [
            {"si-Periodicity": "rf16", "sib-MappingInfo": ["sibType3"]},
            {"si-Periodicity": "rf32", "sib-MappingInfo": ["sibType7"]},
        ],
        "si-WindowLength": "ms20", "systemInfoValueTag": 0,
    }

    def broadcast(value):
        return rrc("BCCH-DL-SCH-Message", 3, {"message": ("c1", ("systemInformationBlockType1", value))})

    complete = broadcast(sib1)
    incomplete = copy.deepcopy(sib1)
    incomplete["schedulingInfoList"] = incomplete["schedulingInfoList"][:1]
    case("SIB1 produces Low test event", 6, "Low", [complete])
    case("Non-SIB1 does not produce test event", 6, None, [security("eea2")])
    case("Short SIB1 schedule is informational", 5, "Informational", [broadcast(incomplete)])
    case("Complete SIB1 schedule is not malformed", 5, None, [complete])

    def priority(lte, legacy):
        return rrc("BCCH-DL-SCH-Message", 3, {"message": ("c1", ("systemInformation", {
            "criticalExtensions": ("systemInformation-r8", {"sib-TypeAndInfo": [
                ("sib3", {
                    "cellReselectionInfoCommon": {"q-Hyst": "dB0"},
                    "cellReselectionServingFreqInfo": {"threshServingLow": 0, "cellReselectionPriority": lte},
                    "intraFreqCellReselectionInfo": {
                        "q-RxLevMin": -60, "presenceAntennaPort1": False,
                        "neighCellConfig": (bytes(1), 2), "t-ReselectionEUTRA": 0,
                    },
                }),
                ("sib7", {
                    "t-ReselectionGERAN": 0,
                    "carrierFreqsInfoList": [{
                        "carrierFreqs": geran,
                        "commonInfo": {
                            "cellReselectionPriority": legacy, "ncc-Permitted": (bytes(1), 8),
                            "q-RxLevMin": 0, "threshX-High": 0, "threshX-Low": 0,
                        },
                    }],
                }),
            ]}),
        }))})

    case("Higher legacy priority is High", 2, "High", [priority(1, 7), complete])
    case("Lower legacy priority is not downgrade", 2, None, [priority(7, 1), complete])
    case("Equal legacy priority is not downgrade", 2, None, [priority(3, 3), complete])
    args.output.write_text(json.dumps(cases, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Generated {len(cases)} synthetic acceptance cases: {args.output}")


if __name__ == "__main__":
    main()
