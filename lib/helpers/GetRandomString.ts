export default function getRandomString(tokenLength: number): string {
    // eslint-disable-next-line no-bitwise
    return [...Array(tokenLength)].map(i => (~~(Math.random() * 36)).toString(36)).join("");
}
