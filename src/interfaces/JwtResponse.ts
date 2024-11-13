import {type JwtPayload} from 'jsonwebtoken';

/**
 * Response have decoded body and information if was already verified and returned from cache
 */
export type JwtResponse<T extends Record<string, unknown>> = {body: T & JwtPayload; isCached: boolean};
