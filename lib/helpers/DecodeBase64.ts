export default function decodeBase64(encoded: string): string {
    const buffer = Buffer.from(encoded, "base64");

    return buffer.toString("utf-8");
}
