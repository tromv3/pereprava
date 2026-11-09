export namespace backup {
	
	export class Header {
	    format: string;
	    version: number;
	    created: string;
	    server: string;
	    host: string;
	    n: number;
	    r: number;
	    p: number;
	    salt: number[];
	    nonce: number[];
	
	    static createFrom(source: any = {}) {
	        return new Header(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.format = source["format"];
	        this.version = source["version"];
	        this.created = source["created"];
	        this.server = source["server"];
	        this.host = source["host"];
	        this.n = source["n"];
	        this.r = source["r"];
	        this.p = source["p"];
	        this.salt = source["salt"];
	        this.nonce = source["nonce"];
	    }
	}

}

export namespace main {
	
	export class ServerInput {
	    id: string;
	    name: string;
	    host: string;
	    port: number;
	    user: string;
	    authType: string;
	    keyPath: string;
	    password: string;
	    passphrase: string;
	    sudoPassword: string;
	
	    static createFrom(source: any = {}) {
	        return new ServerInput(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.user = source["user"];
	        this.authType = source["authType"];
	        this.keyPath = source["keyPath"];
	        this.password = source["password"];
	        this.passphrase = source["passphrase"];
	        this.sudoPassword = source["sudoPassword"];
	    }
	}
	export class ServerView {
	    id: string;
	    name: string;
	    host: string;
	    port: number;
	    user: string;
	    authType: string;
	    keyPath: string;
	    fingerprint: string;
	    hasPassword: boolean;
	    hasSudo: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ServerView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.user = source["user"];
	        this.authType = source["authType"];
	        this.keyPath = source["keyPath"];
	        this.fingerprint = source["fingerprint"];
	        this.hasPassword = source["hasPassword"];
	        this.hasSudo = source["hasSudo"];
	    }
	}

}

