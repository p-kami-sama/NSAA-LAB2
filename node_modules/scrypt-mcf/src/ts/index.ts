/**
 * Scrypt using MCF for both browsers and Node.js
 *
 * @packageDocumentation
 */
import { decode as b64decode, encode as b64encode } from '@juanelas/base64'
import { salt as getRandomSalt, scrypt, ScryptParams as ScryptPbkdfParams } from 'scrypt-pbkdf'

export interface ScryptParams {
  logN?: number
  r?: number
  p?: number
}

export interface ScryptMcfOptions {
  saltBase64NoPadding?: string // a scrypt salt (16 bytes) in base64 with no padding (22 characters)
  derivedKeyLength?: number // the expected length of the output key
  scryptParams?: ScryptParams // scrypt parameters
}

/**
 * Computes a MFC string derived using scrypt on input password
 *
 * @param password - the password
 * @param options - optional 16 bytes/22 characters salt in base64 with no padding (a fresh random one is created if not provided), derivedKeyLength (defaults to 32 bytes), and scrypt parameters (defaults to { logN: 17, r: 8, p: 1 })
 * @returns a MFC string with the format $scrypt$ln=<cost>,r=<blocksize>,p=<parallelism>$<salt in base64 no padding>$<hash in base64 no padding>
 */
export async function hash (password: string, options?: ScryptMcfOptions): Promise<string> {
  const scryptParams: Required<ScryptParams> = {
    logN: 17,
    r: 8,
    p: 1,
    ...options?.scryptParams
  }
  const scryptPbkdfParams: ScryptPbkdfParams = {
    N: 2 ** scryptParams.logN,
    r: scryptParams.r,
    p: scryptParams.p
  }
  const S = (options?.saltBase64NoPadding !== undefined) ? b64decode(options.saltBase64NoPadding) : getRandomSalt()
  const SBase64 = b64encode(S, false, false)
  const derivedKeyLength = options?.derivedKeyLength ?? 32
  const hash = b64encode(await scrypt(password, S, derivedKeyLength, scryptPbkdfParams), false, false)
  return `$scrypt$ln=${scryptParams.logN},r=${scryptParams.r},p=${scryptParams.p}$${SBase64}$${hash}`
}

/**
 * Verify if provided password meets the stored hash (in MCF)
 * @param mcf - a MFC string with the format $scrypt$ln=<cost>,r=<blocksize>,p=<parallelism>$<salt in base64 no padding>$<hash in base64 no padding>
 * @param password - the password to test
 * @returns
 */
export async function verify (password: string, mcf: string): Promise<boolean> {
  const regex = /^\$scrypt\$ln=(\d{1,2}),r=(\d{1,2}),p=(\d{1,2})\$([a-zA-Z0-9/+]{22})\$([a-zA-Z0-9/+]{22,})$/g

  const matches = [...mcf.matchAll(regex)]

  if (matches.length !== 1) {
    throw new Error('Invalid MCFstring format')
  }

  const logN = Number(matches[0][1])
  const r = Number(matches[0][2])
  const p = Number(matches[0][3])
  const S = matches[0][4]
  const derivedKeyLength = 2 ** (Math.floor(Math.log2(matches[0][5].length * 6)) - 3)

  const passwordMfc = await hash(password, {
    saltBase64NoPadding: S,
    scryptParams: { logN, r, p },
    derivedKeyLength
  })

  return passwordMfc === mcf
}
