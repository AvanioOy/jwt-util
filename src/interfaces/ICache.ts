export interface ICache<Payload> {
	get: (key: string) => Payload | undefined;
	set: (key: string, value: Payload, ttl?: number) => void;
	delete: (key: string) => void;
	clear: () => void;
}
