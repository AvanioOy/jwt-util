/* eslint-disable @typescript-eslint/no-explicit-any */
import type * as jwt from 'jsonwebtoken';

export type TokenPayload<T = Record<string, any>> = jwt.JwtPayload & T;
export type TokenIssuerPayload<T = Record<string, any>> = Omit<jwt.JwtPayload, 'iss'> & {iss: string} & T;

export type TokenHeader = {
	[key: string]: any;
	kid?: string;
	alg: jwt.Algorithm | undefined;
	typ: string | undefined;
};

export type FullDecodedTokenStructure = {
	header: jwt.JwtHeader;
	payload: jwt.JwtPayload;
};

export type FullDecodedIssuerTokenStructure = {
	header: jwt.JwtHeader;
	payload: TokenIssuerPayload;
};

/**
 * Checks if the decoded token is a FullDecodedIssuerTokenStructure.
 * @param decoded - The token to check.
 * @returns True if the token is a FullDecodedIssuerTokenStructure, otherwise false.
 */
export function isIssuerToken(decoded: unknown): decoded is FullDecodedIssuerTokenStructure {
	return isTokenFullDecoded(decoded) && typeof decoded.payload.iss === 'string';
}

/**
 * Checks if the decoded token is a FullDecodedTokenStructure.
 * @param decoded - The token to check.
 * @returns True if the token is a FullDecodedTokenStructure, otherwise false.
 */
export function isTokenFullDecoded(decoded: unknown): decoded is FullDecodedTokenStructure {
	return (
		typeof decoded === 'object' &&
		decoded !== null &&
		'payload' in decoded &&
		typeof decoded.payload === 'object' &&
		'header' in decoded &&
		typeof decoded.header === 'object' &&
		'signature' in decoded &&
		typeof decoded.signature === 'string'
	);
}
