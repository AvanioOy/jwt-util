interface IJwkKey {
	alg?: string;
	kty: string;
	use: string;
	kid: string;
	x5t?: string;
	n: string;
	e: string;
	x5c?: string[];
	issuer?: string;
}

export interface IJwtKeys {
	keys: IJwkKey[];
}
