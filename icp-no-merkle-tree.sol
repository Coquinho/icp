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
    function gen_key(uint key, uint n_keys) has_name pay_cust
    public payable returns(bytes32 private_key) {
        private_key = keccak256(abi.encodePacked(key, msg.sender));
        bytes32 public_key = private_key;
        for (uint i = 0; i < n_keys; i++) {
            public_key = keccak256(abi.encodePacked(public_key));
        }
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
        (key, n) = keys.next_key();
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
    bytes32 public public_key;
    bytes32 private private_key;
    uint uses = 1;
    uint max_use;
    
    constructor(bytes32 private_key_, uint max_use_) public {
        private_key = private_key_;
        public_key = private_key;
        max_use = max_use_;
        for (uint i = 0; i < max_use; i++) {
            public_key = keccak256(abi.encodePacked(public_key));
        }
    }
    
    modifier owner() {
        require(msg.sender == own);
        _;
    }
    
    modifier have_use() {
        require(uses < max_use);
        _;
    }
    
    function next_key() owner have_use public returns(bytes32 key, uint n) {
        key = private_key;
        for (uint i = 0; i < max_use-uses; i++) {
            key = keccak256(abi.encodePacked(key));
        }
        n = uses++;
    }
    
    function update_key(bytes32 private_key_, uint max_use_) owner public {
        private_key = private_key_;
        public_key = private_key;
        max_use = max_use_;
        for (uint i = 0; i < max_use; i++) {
            public_key = keccak256(abi.encodePacked(public_key));
        }
    }
}
