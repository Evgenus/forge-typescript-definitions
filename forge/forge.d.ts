declare module forge {

    module util {
        function setImmediate(func: Function): number;
        function nextTick(func: Function): number;
        function isArray(x: any): boolean;
        function isArrayBuffer(x: any): boolean;
        function isArrayBufferView(x: any): boolean;

        interface BufferInterface<T> {
            length(): number;
            isEmpty(): boolean;
            putByte(b: number): T;
            fillWithByte(b: number, n: number): T;

            putString(str: string): T;

            putInt16(i: number): T;
            putInt24(i: number): T;
            putInt32(i: number): T;

            putInt16Le(i: number): T;
            putInt24Le(i: number): T;
            putInt32Le(i: number): T;

            putInt(i: number, n: number): T;
            putSignedInt(i: number, n: number): T;

            getByte(): number;

            getInt16(): number;
            getInt24(): number;
            getInt32(): number;

            getInt16Le(): number;
            getInt24Le(): number;
            getInt32Le(): number;

            getInt(n: number): number;
            getSignedInt(n: number): number;

            getBytes(count: number): string;
            bytes(count: number): string;
            at(i: number): number;
            setAt(i: number, b: number): T;
            last(): number;
            copy(): T;

            compact(): T;
            clear(): T;
            truncate(count: number): T;
            toHex(): string;
            toString(encoding?: number): string
        }

        interface ByteBuffer extends BufferInterface<ByteBuffer> {
            putBytes(bytes: string): ByteBuffer;
            putBuffer<T>(buffer: BufferInterface<T>): ByteBuffer;
        }

        interface ByteBufferStatic {
            new (): ByteBuffer;
            new (b: string): ByteBuffer;
            new (b: ArrayBuffer): ByteBuffer;
            new (b: ArrayBufferView): ByteBuffer;
            new<T> (b: Array<T>): ByteBuffer;
            new (b: ByteBuffer): ByteBuffer;
        }

        var ByteBuffer: ByteBufferStatic;
        var ByteStringBuffer: ByteBufferStatic;
    }

    interface Hash<T> {
        algorithm: string;
        blockLength: number;
        digestLength: number;
        messageLength: number;
        messageLength64: number[]; // array of 2 numbers

        start(): T;
        update(msg: string, encoding?: string): T;
        digest(): forge.util.ByteBuffer;
    }

    interface MD5 extends Hash<MD5> {
    }

    interface SHA1 extends Hash<SHA1> {
    }

    interface SHA224 extends Hash<SHA224> {
    }

    interface SHA256 extends Hash<SHA256> {
    }

    interface SHA384 extends Hash<SHA384> {
    }

    interface SHA512 extends Hash<SHA512> {
    }

    module md5 {
        function create(): MD5;
    }

    module sha1 {
        function create(): SHA1;
    }

    module sha224 {
        function create(): SHA224;
    }

    module sha256 {
        function create(): SHA256;
    }

    module sha384 {
        function create(): SHA384;
    }

    module sha512 {
        export import sha384 = forge.sha384;
        export import sha224 = forge.sha224;
        function create(): SHA512;
    }

    module md {
        module algorithms {
            export import md5 = forge.md5;
            export import sha1 = forge.sha1;
            export import sha256 = forge.sha256;
            export import sha384 = forge.sha384;
            export import sha512 = forge.sha512;
        }
        export import md5 = forge.md5;
        export import sha1 = forge.sha1;
        export import sha256 = forge.sha256;
        export import sha384 = forge.sha384;
        export import sha512 = forge.sha512;
    }

    interface MaskGenerator {
        generate(seed: string, maskLen: number): string;
    }

    interface MGF1 extends MaskGenerator {
    }

    module mgf1 {
        function create<T>(md: Hash<T>): MGF1;
    }

    module mgf {
        export import mgf1 = forge.mgf1;
    }

    interface HMAC {
        start(): void;
        start<T>(md: Hash<T>): void;
        start<T>(md: Hash<T>, key: string): void;
        start<T>(md: Hash<T>, key: number[]): void;
        start<T>(md: Hash<T>, key: util.ByteBuffer): void;
        start(md: string): void;
        start(md: string, key: string): void;
        start(md: string, key: number[]): void;
        start(md: string, key: util.ByteBuffer): void;

        update(bytes: string): void;

        getMac(): util.ByteBuffer;
    }

    module hmac {
        function create(): HMAC;
    }
}
