pragma solidity ^0.4.24;

contract CA {
    address maintainer = msg.sender;
    address master = this;
    Storage_key keys;
    bool public valid = true;

    uint cust = 1 wei;
    uint acc = 0;

    address[] cot;

    constructor(uint key, uint uses) public {
        bytes32 pk = keccak256(abi.encodePacked(msg.sender, key, now));
        keys = new Storage_key(pk, uses);
    }

    struct Timestamp {
        address signer;
        bytes32 key;
        bytes32 hash;
        uint data;
        bool init;
    }

    struct Key_adress {
        address adss;
        bool valid;
    }

    struct Certificate {
        string name;
        string email;
        bool init;
    }

    mapping (bytes32 => Timestamp) timestamps;
    mapping (bytes32 => Timestamp) hash_timestamps;
    mapping (bytes32  => Key_adress) public_keys;
    mapping (address => Certificate) names;

    modifier is_a(address adss) {
        require(msg.sender == adss);
        _;
    }
    modifier has_name() {
        require(names[msg.sender].init);
        _;
    }
    modifier pay_cust() {
        require(msg.value == cust);
        _;
        acc += msg.value;
    }
    modifier unused_key(bytes32 key) {
        require(!timestamps[key].init);
        _;
    }
    modifier gtz(uint n) {
        require(n > 0);
        _;
    }

    function get_master() constant public returns (address) {
        return master;
    }
    function set_master(address adss) is_a(maintainer) public {
        master = adss;
    }
    function assing_name(address adss, string name, string email)
    is_a(maintainer) public {
        names[adss] = Certificate(name, email, true);
    }

    function merkletree(bytes32 seed, uint numkeys) pure
    private returns(bytes32 keyzero, bytes32 root) {
        bytes32[] memory zkeys;

        // found relevante keys to merkle proof
        if (numkeys % 2 == 0) {
            numkeys /= 2;
            // get to the first odd key
            keyzero = keccak256(abi.encodePacked(seed));
        } else {
            numkeys = (numkeys+1)/2;
            keyzero = seed;
        }

        // hash the first odd key to merkle tree
        zkeys[numkeys-1] = keccak256(abi.encodePacked(keyzero));

        for (uint i = numkeys-2; i >= 0 ; i--) {
            // 2 hashes to jump for the next odd index
            keyzero = keccak256(abi.encodePacked(keccak256(abi.encodePacked(keyzero))));
            // hash key to a leaf of the merkle tree
            zkeys[i] = keccak256(abi.encodePacked(keyzero));
        }
        // keyzero and the most left leaf from merkle tree are the same
        keyzero = keccak256(abi.encodePacked(keyzero));

        // implementing merkle tree proof
        while(numkeys > 1) {
            // number of nodes in the next tree level
            if (numkeys % 2 == 0)
                numkeys /= 2;
            else
                numkeys = (numkeys+1)/2;

            for (i = 0; i < numkeys-numkeys%2; i++) {
                zkeys[i] = keccak256(abi.encodePacked(zkeys[2*i],zkeys[2*i+1]));
            }
            if(numkeys%2 == 1)
                zkeys[(numkeys+1)/2] = zkeys[numkeys];

        }

        root = zkeys[0];
    }

    function verifytree(bytes32 key, bytes32[] chain, uint index)
    pure private returns(bytes32 keyzero, bytes32 root) {

        bytes32[] memory zkeys;

        // found relevante keys to merkle proof
        if (index % 2 == 0) {
            index /= 2;
            // get to the first odd key
            keyzero = keccak256(abi.encodePacked(keyzero));
        } else {
            index = (index+1)/2;
            keyzero = key;
        }

        // hash the first odd key to merkle tree
        zkeys[index-1] = keccak256(abi.encodePacked(keyzero));

        for (uint i = index-2; i >= 0 ; i--) {
            // 2 hashes to jump for the next odd index
            keyzero = keccak256(abi.encodePacked(keccak256(abi.encodePacked(keyzero))));
            // hash key to a leaf of the merkle tree
            zkeys[i] = keccak256(abi.encodePacked(keyzero));
        }
        // keyzero and the most left leaf from merkle tree are the same
        keyzero = keccak256(abi.encodePacked(keyzero));

        uint chainindex = 0;

        // numoperation is the number of operations that can be done with out
        //     chain
        uint numoperation = 0;
        // merkle tree proof
        while(index > 1) {
            // index is the number of nodes in the next tree layer
            if (index % 2 == 0) {
                index /= 2;
                numoperation = index;
            } else {
                index = (index+1)/2;
                numoperation = index-1;
            }

            // hashes leaves two by two
            for (i = 0; i < numoperation; i++) {
                zkeys[i] = keccak256(abi.encodePacked(zkeys[2*i],zkeys[2*i+1]));
            }
            if(numoperation%2 == 1) {
                zkeys[(index+1)/2] = keccak256(abi.encodePacked(zkeys[index],chain[chainindex]));
                chainindex++;
            }

        }

        root = zkeys[0];
    }
    function gen_key(uint key, uint n_keys) has_name pay_cust
    public payable returns(bytes32 private_key, bytes32 public_key) {
        private_key = keccak256(abi.encodePacked(key, msg.sender));

        bytes32 key0;
        bytes32 root;
        (key0, root) = merkletree(private_key, n_keys);
        public_key = keccak256(abi.encodePacked(key0,root));
        public_keys[public_key] = Key_adress(msg.sender, true);
    }
    function sign(bytes32 key, uint n, bytes32 hash)
    has_name unused_key(key) gtz(n) public returns(bool) {
        bytes32 pk = key;
        for (uint i = 0; i < n-1; i++) {
            pk = keccak256(abi.encodePacked(pk));
            if (!timestamps[pk].init) {
                return false;
            }
        }

        pk = keccak256(abi.encodePacked(pk));
        if (msg.sender != public_keys[pk].adss || !public_keys[pk].valid) {
            return false;
        }

        timestamps[key] = Timestamp(msg.sender, key, hash, now, true);
        hash_timestamps[hash] = Timestamp(msg.sender, key, hash, now, true);
        return true;
    }
    function verify(bytes32 hash) constant public
    returns (address, bytes32, bytes32, uint) {
        Timestamp memory t = hash_timestamps[hash];
        if (t.init && public_keys[t.key].valid) {
            return (t.signer, t.key, t.hash, t.data);
        } else {
            return;
        }
    }

    function update_chain() is_a(maintainer) public{
        delete cot;
        cot.push(this);

        CA ca = CA(master);
        CA sca = this;

        while (address(ca) != address(sca)) {
            bytes32 hash_sca = keccak256(abi.encodePacked(address(sca)));

            (address adss,,,) = ca.verify(hash_sca);
            if (adss == address(ca) && ca.valid()) {
                cot.push(address(ca));
            } else {
                break;
            }
            sca = ca;
            ca = CA(ca.get_master());
        }
    }

    function get_chain() constant public returns (address[]) {
        return cot;
    }

    function sign_ca(address ca) is_a(maintainer) public returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(ca));
        bytes32 key;
        uint n;
        bytes32[] memory chain;
        (key, n, chain) = keys.next_key();
        bytes32 pk = key;
        for (uint i = 0; i < n-1; i++) {
            pk = keccak256(abi.encodePacked(pk));
            if (!timestamps[pk].init) {
                return false;
            }
        }

        pk = keccak256(abi.encodePacked(pk));
        if (pk != keys.public_key()) {
            return false;
        }

        timestamps[key] = Timestamp(this, key, hash, now, true);
        hash_timestamps[hash] = Timestamp(this, key, hash, now, true);
        return true;
    }

    modifier own_key(bytes32 public_key) {
       Key_adress memory key = public_keys[public_key];
        require(key.adss == msg.sender);
        _;
    }

    function revok(bytes32 public_key) own_key(public_key) public {
        public_keys[public_key].valid = false;
    }

    function revok_ca() is_a(maintainer) public {
        valid = false;
    }
}


contract Storage_key {

    address own = msg.sender;
    bytes32 private private_key;
    bytes32 public public_key;
    uint uses = 0;
    uint max_use;

    constructor(bytes32 private_key_, uint max_use_) public {
        private_key = private_key_;
        max_use = max_use_;
        bytes32 key;
        bytes32 root;
        (key, root) = merkletree(private_key, max_use);
        public_key = keccak256(abi.encodePacked(key,root));
    }

    modifier owner() {
        require(msg.sender == own);
        _;
    }

    modifier have_use() {
        require(uses < max_use);
        _;
    }

    function next_key() owner have_use public
    returns(bytes32 key, uint index, bytes32[] chain) {
        bytes32[] memory zkeys;

        uses++;
        key = private_key;

        // found relevante keys to the chain
        if (max_use % 2 == 0)
            index = max_use/2;
        else
            index = (max_use+1)/2;
        if (uses % 2 == 0) {
            index -= uses/2;
            // get to the first odd key
            key = keccak256(abi.encodePacked(key));
        } else
            index -= (uses+1)/2;


        // hash the first odd key to merkle tree
        zkeys[index] = keccak256(abi.encodePacked(key));

        for (uint i = index-1; i > 0 ; i--) {
            // 2 hashes to jump for the next odd index
            key = keccak256(abi.encodePacked(keccak256(abi.encodePacked(key))));
            // hash key to a leaf of the merkle tree
            zkeys[i] = keccak256(abi.encodePacked(key));
        }

        if(index%2==0)
            key =  keccak256(abi.encodePacked(key));

        uint chainindex = 0;

        // numoperation is the number of operations that can be done with out
        //     chain
        uint numoperation = 0;

        // generate the chain for the merkle tree proof
        while(index > 1) {
            // index is the number of nodes in the next tree layer
            if (index % 2 == 0) {
                index /= 2;
                numoperation = index;
            } else {
                index = (index+1)/2;
                numoperation = index-1;
            }

            // hashes leaves two by two
            for (i = index-numoperation+chainindex-1; i < numoperation; i++) {
                zkeys[i] = keccak256(abi.encodePacked(zkeys[2*i],zkeys[2*i+1]));
            }
            if(numoperation%2 == 1) {
                zkeys[(numoperation+1)/2] = zkeys[numoperation+1];
                chain[chainindex] = zkeys[chainindex];
                chainindex++;
            }

        }
    }

    function update_key(bytes32 private_key_, uint max_use_) owner public{
        private_key = private_key_;
        max_use = max_use_;
        bytes32 key;
        bytes32 root;
        (key, root) = merkletree(private_key, max_use);
        public_key = keccak256(abi.encodePacked(key,root));
    }

    function merkletree(bytes32 seed, uint numkeys) pure
    private returns(bytes32 keyzero, bytes32 root) {
        bytes32[] memory zkeys;

        // found relevante keys to merkle proof
        if (numkeys % 2 == 0) {
            numkeys /= 2;
            // get to the first odd key
            keyzero = keccak256(abi.encodePacked(seed));
        } else {
            numkeys = (numkeys+1)/2;
            keyzero = seed;
        }

        // hash the first odd key to merkle tree
        zkeys[numkeys-1] = keccak256(abi.encodePacked(keyzero));

        for (uint i = numkeys-2; i >= 0 ; i--) {
            // 2 hashes to jump for the next odd index
            keyzero = keccak256(abi.encodePacked(keccak256(abi.encodePacked(keyzero))));
            // hash key to a leaf of the merkle tree
            zkeys[i] = keccak256(abi.encodePacked(keyzero));
        }
        // keyzero and the most left leaf from merkle tree are the same
        keyzero = keccak256(abi.encodePacked(keyzero));

        // implementing merkle tree proof
        while(numkeys > 1) {
            // number of nodes in the next tree level
            if (numkeys % 2 == 0)
                numkeys /= 2;
            else
                numkeys = (numkeys+1)/2;

            for (i = 0; i < numkeys-numkeys%2; i++) {
                zkeys[i] = keccak256(abi.encodePacked(zkeys[2*i],zkeys[2*i+1]));
            }
            if(numkeys%2 == 1)
                zkeys[(numkeys+1)/2] = zkeys[numkeys];

        }

        root = zkeys[0];
    }

    function verifytree(bytes32 key, bytes32[] chain, uint index)
    pure private returns(bytes32 keyzero, bytes32 root) {

        bytes32[] memory zkeys;

        // found relevante keys to merkle proof
        if (index % 2 == 0) {
            index /= 2;
            // get to the first odd key
            keyzero = keccak256(abi.encodePacked(keyzero));
        } else {
            index = (index+1)/2;
            keyzero = key;
        }

        // hash the first odd key to merkle tree
        zkeys[index-1] = keccak256(abi.encodePacked(keyzero));

        for (uint i = index-2; i >= 0 ; i--) {
            // 2 hashes to jump for the next odd index
            keyzero = keccak256(abi.encodePacked(keccak256(abi.encodePacked(keyzero))));
            // hash key to a leaf of the merkle tree
            zkeys[i] = keccak256(abi.encodePacked(keyzero));
        }
        // keyzero and the most left leaf from merkle tree are the same
        keyzero = keccak256(abi.encodePacked(keyzero));

        uint chainindex = 0;

        // numoperation is the number of operations that can be done with out
        //     chain
        uint numoperation = 0;
        // merkle tree proof
        while(index > 1) {
            // index is the number of nodes in the next tree layer
            if (index % 2 == 0) {
                index /= 2;
                numoperation = index;
            } else {
                index = (index+1)/2;
                numoperation = index-1;
            }

            // hashes leaves two by two
            for (i = 0; i < numoperation; i++) {
                zkeys[i] = keccak256(abi.encodePacked(zkeys[2*i],zkeys[2*i+1]));
            }
            if(numoperation%2 == 1) {
                zkeys[(index+1)/2] = keccak256(abi.encodePacked(zkeys[index],chain[chainindex]));
                chainindex++;
            }

        }

        root = zkeys[0];
    }
}
