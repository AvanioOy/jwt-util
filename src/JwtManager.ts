import {AuthHeader, isAuthHeaderLikeString} from '@avanio/auth-header';
import {decode, type Jwt, type JwtPayload, type VerifyOptions} from 'jsonwebtoken';
import {ExpireCache} from '@avanio/expire-cache';
import {type IAsyncCache} from '@luolapeikko/cache-types';
import {type IIssuerManager} from './interfaces/IIssuerManager';
import {type ILoggerLike} from '@avanio/logger-like';
import {JwtBodyError} from './lib/JwtBodyError';
import {JwtError} from './lib/JwtError';
import {JwtHeaderError} from './lib/JwtHeaderError';
import {type JwtResponse} from './interfaces/JwtResponse';
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
	private cache: IAsyncCache<JwtPayload>;

	constructor(issuerManager: IIssuerManager, cache?: IAsyncCache<JwtPayload>, options: JwtManagerOptions = {}) {
		this.issuerManager = issuerManager;
		this.cache = cache || new ExpireCache<JwtPayload>();
		this.options = options;
	}

	/**
	 * JWT verify and cache
	 * @param tokenOrBearer token or bearer string
	 * @param options Jwt verify options
	 * @param jwtBodyValidation callback to validate decoded jwt body before caching, must throw error if validation fails
	 * @returns Jwt response with decoded body and isCached flag
	 * @example
	 * const {isCached, body} = await jwt.verify(tokenString, undefined, (body) => googleIdTokenZodSchema.strict().parse(body));
	 */
	public async verify<T extends Record<string, unknown>>(
		tokenOrBearer: string,
		options: VerifyOptions = {},
		jwtBodyValidation?: (jwtBody: unknown) => T,
	): Promise<JwtResponse<T>> {
		try {
			const currentToken = isAuthHeaderLikeString(tokenOrBearer) ? AuthHeader.fromString(tokenOrBearer) : tokenOrBearer;
			// only allow bearer as auth type
			if (currentToken instanceof AuthHeader && currentToken.type !== 'BEARER') {
				throw new JwtHeaderError('token header: wrong authentication header type');
			}
			const token = currentToken instanceof AuthHeader ? currentToken.credentials : currentToken;
			const cached = (await this.cache.get(token)) as (T & JwtPayload) | undefined;
			if (cached) {
				return {body: cached, isCached: true};
			}
			const secretOrPublicKey = await this.getSecretOrPublicKey(token);
			const verifiedDecode = (await jwtVerifyPromise(token, secretOrPublicKey, options)) as T & JwtPayload;
			jwtBodyValidation?.(verifiedDecode);
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
		const payload = decoded.payload || {};
		if (typeof payload === 'string') {
			throw new JwtBodyError('token body: invalid token');
		}
		const {kid} = decoded.header;
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
