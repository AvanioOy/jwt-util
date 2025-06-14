import {EventEmitter} from 'events';
import {ExpireCache} from '@avanio/expire-cache';
import {type ILoggerLike} from '@avanio/logger-like';
import {AuthHeader, isAuthHeaderString} from '@luolapeikko/auth-header';
import {type IAsyncCache, type IAsyncCacheWithEvents} from '@luolapeikko/cache-types';
import {decode, type Jwt, type JwtPayload, type VerifyOptions} from 'jsonwebtoken';
import {type IIssuerManager} from './interfaces/IIssuerManager';
import {type JwtResponse} from './interfaces/JwtResponse';
import {jwtVerifyPromise} from './lib/jwt';
import {JwtBodyError} from './lib/JwtBodyError';
import {JwtError} from './lib/JwtError';
import {JwtHeaderError} from './lib/JwtHeaderError';

export type JwtManagerEventMapping = {
	add: [JwtPayload];
	expire: [JwtPayload];
};

type JwtManagerOptions = {
	logger?: ILoggerLike;
};

function isEventCache(cache: IAsyncCache<JwtPayload> | IAsyncCacheWithEvents<JwtPayload>): cache is IAsyncCacheWithEvents<JwtPayload> {
	return cache instanceof EventEmitter;
}

/**
 * Jwt manager verifies and caches validated jwt tokens
 * @example
 * const jwt = new JwtManager(new IssuerManager([new JwtAsymmetricDiscoveryTokenIssuer(['https://accounts.google.com'])]))
 * const {isCached, body} = await jwt.verify(token);
 */
export class JwtManager extends EventEmitter<JwtManagerEventMapping> {
	private issuerManager: IIssuerManager;
	private options: JwtManagerOptions;
	public readonly cache: IAsyncCache<JwtPayload> | IAsyncCacheWithEvents<JwtPayload>;

	public constructor(issuerManager: IIssuerManager, cache?: IAsyncCache<JwtPayload> | IAsyncCacheWithEvents<JwtPayload>, options: JwtManagerOptions = {}) {
		super();
		this.issuerManager = issuerManager;
		this.cache = cache ?? new ExpireCache<JwtPayload>();
		this.options = options;
		// hook cache events to emit events
		if (isEventCache(this.cache)) {
			this.cache.on('set', (_key, payload) => this.emit('add', payload));
			this.cache.on('expires', (_key, payload) => this.emit('expire', payload));
		}
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
			const currentToken = isAuthHeaderString(tokenOrBearer) ? AuthHeader(tokenOrBearer).unwrap() : tokenOrBearer;
			// only allow bearer as auth type
			if (typeof currentToken !== 'string' && currentToken.scheme !== 'BEARER') {
				throw new JwtHeaderError('token header: wrong authentication header type');
			}
			const token = typeof currentToken === 'string' ? currentToken : currentToken.getCredentials();
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
