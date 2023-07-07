import {AuthHeader, isAuthHeaderLikeString} from '@avanio/auth-header';
import {decode, Jwt, JwtPayload, VerifyOptions} from 'jsonwebtoken';
import {ExpireCache, ICacheOrAsync} from '@avanio/expire-cache';
import {IIssuerManager} from './interfaces/IIssuerManager';
import {ILoggerLike} from '@avanio/logger-like';
import {JwtBodyError} from './lib/JwtBodyError';
import {JwtError} from './lib/JwtError';
import {JwtHeaderError} from './lib/JwtHeaderError';
import {JwtResponse} from './interfaces/JwtResponse';
import {jwtVerifyPromise} from './lib/jwt';

type JwtManagerOptions = {
	logger?: ILoggerLike;
};

/**
 * Jwt manager verifies and caches validated jwt tokens
 * @example
 * const jwt = new JwtManager(new IssuerManager([new JwtAsymmetricDiscoveryTokenIssuer(['https://accounts.google.com'])]))
 * const {isCached, body} = await jwt.verify(token);
 */
export class JwtManager {
	private issuerManager: IIssuerManager;
	private options: JwtManagerOptions;
	private cache: ICacheOrAsync<JwtPayload>;

	constructor(issuerManager: IIssuerManager, cache?: ICacheOrAsync<JwtPayload>, options: JwtManagerOptions = {}) {
		this.issuerManager = issuerManager;
		this.cache = cache || new ExpireCache<JwtPayload>();
		this.options = options;
	}

	public async verify<T extends Record<string, unknown>>(tokenOrBearer: string, options: VerifyOptions = {}): Promise<JwtResponse<T>> {
		try {
			const currentToken = isAuthHeaderLikeString(tokenOrBearer) ? AuthHeader.fromString(tokenOrBearer) : tokenOrBearer;
			// only allow bearer as auth type
			if (currentToken instanceof AuthHeader && currentToken.type !== 'BEARER') {
				throw new JwtHeaderError('token header: wrong authentication header type');
			}
			const token = currentToken instanceof AuthHeader ? currentToken.credentials : currentToken;
			const cached = (await this.cache.get(token)) as T & JwtPayload;
			if (cached) {
				return {body: cached, isCached: true};
			}
			const secretOrPublicKey = await this.getSecretOrPublicKey(token);
			const verifiedDecode = (await jwtVerifyPromise(token, secretOrPublicKey, options)) as T & JwtPayload;
			if (verifiedDecode.exp) {
				await this.cache.set(token, verifiedDecode, new Date(verifiedDecode.exp * 1000));
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
