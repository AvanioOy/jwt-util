import {JwtPayload, verify, VerifyErrors} from 'jsonwebtoken';

type JwtVerifyPromiseFunc<T = Record<string, unknown>> = (...params: Parameters<typeof verify>) => Promise<(JwtPayload & T) | undefined>;
export const jwtVerifyPromise: JwtVerifyPromiseFunc = (token, secretOrPublicKey, options?) => {
	return new Promise<JwtPayload | undefined>((resolve, reject) => {
		verify(token, secretOrPublicKey, options, (err: VerifyErrors | null, decoded: object | undefined) => {
			if (err) {
				reject(err);
			} else {
				resolve(decoded);
			}
		});
	});
};
