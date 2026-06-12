import { Noc, DerCodec } from "@matter/protocol";
const hex = process.argv[2];
const noc = Noc.fromTlv(Buffer.from(hex, "hex"));
const tbs = DerCodec.encode(noc.genericBuildAsn1Structure(noc.cert));
console.log(Buffer.from(tbs).toString("hex"));
