import {decode, Jwt, JwtPayload, VerifyOptions} from 'jsonwebtoken';
import {AuthHeader, getTokenOrAuthHeader} from './AuthHeader';
import {ICache, ExpireCache} from '@avanio/expire-cache';
import {JwtHeaderError} from './lib/JwtHeaderError';
import {ILoggerLike} from '@avanio/logger-like';
import {JwtResponse} from './interfaces/JwtResponse';
import {JwtError} from './lib/JwtError';
import {jwtVerifyPromise} from './lib/jwt';
import {IIssuerManager} from './interfaces/IIssuerManager';
import {JwtBodyError} from './lib/JwtBodyError';

type JwtManagerOptions = {
	logger?: ILoggerLike;
};

export class JwtManager {
	private issuerManager: IIssuerManager;
	private options: JwtManagerOptions;
	private cache: ICache<JwtPayload>;
	constructor(issuerManager: IIssuerManager, cache?: ICache<JwtPayload>, options: JwtManagerOptions = {}) {
		this.issuerManager = issuerManager;
		this.cache = cache || new ExpireCache<JwtPayload>();
		this.options = options;
	}

	public async verify<T extends Record<string, unknown>>(tokenOrBearer: string, options: VerifyOptions = {}): Promise<JwtResponse<T>> {
		try {
			const currentToken = getTokenOrAuthHeader(tokenOrBearer);
			// only allow bearer as auth type
			if (currentToken instanceof AuthHeader && currentToken.type !== 'BEARER') {
				throw new JwtHeaderError('token header: wrong authentication header type');
			}
			const token = currentToken instanceof AuthHeader ? currentToken.credentials : currentToken;
			const cached = this.cache.get(token) as T & JwtPayload;
			if (cached) {
				return {body: cached, isCached: true};
			}
			const secretOrPublicKey = await this.getSecretOrPublicKey(token);
			const verifiedDecode = (await jwtVerifyPromise(token, secretOrPublicKey, options)) as T & JwtPayload;
			if (verifiedDecode.exp) {
				this.cache.set(token, verifiedDecode, new Date(verifiedDecode.exp * 1000));
			}
			return {body: verifiedDecode, isCached: false};
		} catch (err) {
			this.options.logger?.error(err);
			throw err;
		}
	}

	private async getSecretOrPublicKey(token: string): Promise<string | Buffer> {
		const {iss, kid} = this.getKid(decode(token, {complete: true}));
		const secretOrPublicKey = await this.issuerManager.get(iss, kid);
		if (!secretOrPublicKey) {
			throw new JwtError('no private key found');
		}
		return secretOrPublicKey;
	}

	private getKid(decoded: null | Jwt): {kid: string; iss: string} {
		if (!decoded) {
			throw new JwtError('empty token');
		}
		const payload = decoded?.payload || {};
		if (typeof payload === 'string') {
			throw new JwtBodyError('token body: invalid token');
		}
		const {kid} = decoded?.header || {};
		const {iss} = payload;
		if (!kid) {
			throw new JwtHeaderError('token header: missing kid parameter');
		}
		if (!iss) {
			throw new JwtBodyError('token body: missing iss parameter');
		}
		return {kid, iss};
	}
}
