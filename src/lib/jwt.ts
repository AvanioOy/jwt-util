import {type JwtPayload, verify, type VerifyErrors} from 'jsonwebtoken';

type JwtVerifyPromiseFunc<T = Record<string, unknown>> = (...params: Parameters<typeof verify>) => Promise<(JwtPayload & T) | undefined>;
export const jwtVerifyPromise: JwtVerifyPromiseFunc = (token, secretOrPublicKey, options?) => {
	return new Promise<JwtPayload | undefined>((resolve, reject) => {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-argument
		verify(token, secretOrPublicKey, options as any, (err: VerifyErrors | null, decoded: object | undefined) => {
			if (err) {
				reject(err);
			} else {
				resolve(decoded);
			}
		});
	});
};
