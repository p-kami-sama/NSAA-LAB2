interface ScryptParams {
    logN?: number;
    r?: number;
    p?: number;
}
interface ScryptMcfOptions {
    saltBase64NoPadding?: string;
    derivedKeyLength?: number;
    scryptParams?: ScryptParams;
}
/**
 * Computes a MFC string derived using scrypt on input password
 *
 * @param password - the password
 * @param options - optional 16 bytes/22 characters salt in base64 with no padding (a fresh random one is created if not provided), derivedKeyLength (defaults to 32 bytes), and scrypt parameters (defaults to { logN: 17, r: 8, p: 1 })
 * @returns a MFC string with the format $scrypt$ln=<cost>,r=<blocksize>,p=<parallelism>$<salt in base64 no padding>$<hash in base64 no padding>
 */
declare function hash(password: string, options?: ScryptMcfOptions): Promise<string>;
/**
 * Verify if provided password meets the stored hash (in MCF)
 * @param mcf - a MFC string with the format $scrypt$ln=<cost>,r=<blocksize>,p=<parallelism>$<salt in base64 no padding>$<hash in base64 no padding>
 * @param password - the password to test
 * @returns
 */
declare function verify(password: string, mcf: string): Promise<boolean>;

export { hash, verify };
export type { ScryptMcfOptions, ScryptParams };
