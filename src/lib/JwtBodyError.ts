import {JwtError} from './JwtError';

export class JwtBodyError extends JwtError {
	constructor(message: string) {
		super(message);
		this.name = 'JwtBodyError';
		Error.captureStackTrace(this, this.constructor);
	}
}
