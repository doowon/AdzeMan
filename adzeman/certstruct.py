from construct import Struct, Byte, Int64ub, Int16ub, GreedyBytes, Enum, Int24ub, Bytes, GreedyRange, Terminated, this

MerkleTreeHeader = Struct(
    "Version"         / Byte,
    "MerkleLeafType"  / Byte,
    "Timestamp"       / Int64ub,
    "LogEntryType"    / Enum(Int16ub, X509LogEntryType=0, PrecertLogEntryType=1),
    "Entry"           / GreedyBytes
)
Certificate = Struct(
    "Length" / Int24ub,
    "CertData" / Bytes(this.Length)
)

CertificateChain = Struct(
    "ChainLength" / Int24ub,
    "Chain" / GreedyRange(Certificate),
)

# PreCertEntry = Struct(
#     "LeafCert" / Certificate,
#     Embedded(CertificateChain),
#     Terminated
# )

class CertData():
    log_timestamp = 0
    ct_index = 0
    all_domains = []
    cert_dump = ""
    not_before = 0
    not_after = 0
    