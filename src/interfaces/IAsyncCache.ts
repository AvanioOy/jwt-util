export interface IAsyncCache<Payload> {
	init: () => Promise<void>;
	get: (key: string) => Promise<Payload | undefined>;
	set: (key: string, value: Payload, ttl?: number) => Promise<void>;
	del: (key: string) => Promise<void>;
	clear: () => Promise<void>;
}
