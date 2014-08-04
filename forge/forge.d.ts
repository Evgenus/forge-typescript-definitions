declare module forge {

    interface ByteBuffer {
    }

    interface Hash<T> {
        algorithm: string;
        blockLength: number;
        digestLength: number;
        messageLength: number;
        messageLength64: number[]; // array of 2 numbers

        start(): T;
        update(msg: string, encoding?: string): T;
        digest(): forge.ByteBuffer;
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
}
