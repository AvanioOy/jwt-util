const AUTH_TYPES = ['BEARER', 'BASIC', 'DIGEST', 'HOBA', 'MUTUAL', 'NEGOTIATE', 'NTLM', 'VAPID', 'AWS4-HMAC-SHA256'] as const;
export type AuthType = typeof AUTH_TYPES[number];

const AuthHeaderMustBeString = 'Auth header must be a string';

export class AuthHeaderError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'AuthHeaderError';
		Error.captureStackTrace(this, this.constructor);
	}
}

/**
 * Type guard for AuthType
 */
export function isAuthType(data: unknown): data is AuthType {
	if (typeof data !== 'string') {
		return false;
	}
	data = data.toUpperCase();
	return AUTH_TYPES.some((t) => t === data);
}

/**
 * Returns the authentication type from the authorization string
 * @param {unknown} value Authorization string
 * @throws AuthHeaderError - If the authentication type is not valid
 * @returns AuthType - Authentication type
 */
export function getAuthType(value: unknown): AuthType {
	if (typeof value !== 'string') {
		throw new AuthHeaderError(`${JSON.stringify(value)} is not string type`);
	}
	value = value.toUpperCase();
	if (!isAuthType(value)) {
		throw new AuthHeaderError(`${value} is not valid auth header type`);
	}
	return value;
}

/**
 * return AuthHeader instance or string
 */
export function getTokenOrAuthHeader(data: unknown): string | AuthHeader {
	if (typeof data !== 'string') {
		throw new AuthHeaderError(AuthHeaderMustBeString);
	}
	return AuthHeader.isAuthHeader(data) ? AuthHeader.fromString(data) : data;
}

export function getAuthHeader(data: unknown): AuthHeader {
	if (typeof data !== 'string') {
		throw new AuthHeaderError(AuthHeaderMustBeString);
	}
	return AuthHeader.fromString(data);
}

export class AuthHeader {
	private readonly auth: string;
	public readonly type: AuthType;
	public readonly credentials: string;

	public static isAuthHeader(auth: unknown): auth is string {
		if (typeof auth !== 'string') {
			return false;
		}
		const [type] = auth.split(' ', 2);
		return isAuthType(type);
	}

	public static fromString(auth: string): AuthHeader {
		if (typeof auth !== 'string') {
			throw new AuthHeaderError(AuthHeaderMustBeString);
		}
		return new AuthHeader(auth);
	}

	private constructor(auth: string) {
		const [type, credentials] = auth.split(' ', 2);
		this.auth = auth;
		this.type = getAuthType(type);
		this.credentials = credentials;
	}

	public toString(): string {
		return this.auth;
	}
}
