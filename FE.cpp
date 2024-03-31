/*This is an implementation of Inner Product Functional Encryption 
Under DDH Assumption

The implementation is based on the paper: "Simple Functional 
Encryption Schemes for Inner Products", 
found at https://eprint.iacr.org/2015/017.pdf

Please refer to Section 5 of the paper for technical details about
how to build inner product functional encryption on top of ElGamal 
encryption schemes
*/

/*This program requires gmp library to provide the functionalities
for arithmetics of big integers
Please refer to https://gmplib.org/ for technical details of GMP 
library
*/
#include<gmp.h>
#include<cstdlib>
#include<iostream>

using namespace std;

class FE_inner_product_DDH;

/*Inner product functional encryption is built upon public key 
encryption scheme, the ElGamal encryption scheme

So, first we implement functionalities for ElGamal encryption 
scheme, then we encapsulate ElGamal scheme in our inner product
functional encryption scheme.
*/

class cipher_text{//cipher text for ElGamal
public:
    mpz_t c0;
    mpz_t c1;
    cipher_text(){
        mpz_init(c0);mpz_init(c1);
    }
};

class plain_text{//plain text for both ElGamal and FE
public:
    mpz_t msg;
    plain_text(){
        mpz_init(msg);
    }
};

class commitment{//commitment for ElGamal
public:
    mpz_t rand;
    commitment(){
        mpz_init(rand);
    }
};

/*The class ElGamal_Param provides "common knowledge" for all 
ElGamal clients. It is instantiated before creation of any 
ElGamal clients. Every ElGamal client has a static member of
this class.
*/
class ElGamal_Param{
private:
    const unsigned int reps=50;//a threshold for prime test functions. Not in use in current implementation
    unsigned int seed;//provide the seed to initialize pseudo-random generator
public:
    const unsigned int bit_length=64;//define that each number should be of 64-bit long in ElGamal
    gmp_randstate_t state;//This is for initialization of pseudo-random generator
    mpz_t p,g;//the common parameters, the prime number p, and the generator of Z_{p}, g.

    ElGamal_Param(){
        gmp_randinit_mt(state);
        seed = (unsigned int)time(NULL);
        gmp_randseed_ui(state,seed);//initialize the pseudo-random generator
        mpz_init(p);mpz_init(g);
        mpz_set_ui(p,73);//set prime number p
        mpz_set_ui(g,15);//set generator g
        /*This implementation is only for demo purpose. For more practical use, we might need to generate 
        large random numbers and use prime test to probabilistically guarantee that it is a desired prime
        number p. Below is a possible version of codes to generate such large prime number p.
        do
        {
            mpz_urandomb(p,state,bit_length);
        } while (mpz_sizeinbase(p,2)<bit_length || mpz_probab_prime_p(p,reps)==0);
        mpz_urandomb(g,state,bit_length);
        mpz_mod(g,g,p);
        To find a generator for the large prime number p, we need advanced cryptography algorithms, which
        is omitted here.
        */
    }
};

class ElGamal_Client{
    friend class FE_inner_product_DDH;
private:
    mpz_t x;//private key
    /*gcdExtended receives c0, p, and computes c0 * inv + p * co_inv = gcd where gcd is the greatest common divisor
    when gcd = 1, inv is the inverse of c0 modular p.
    */
    void gcdExtended(mpz_t c0, mpz_t p, mpz_t *inv, mpz_t *co_inv, mpz_t *gcd){
        if(mpz_cmp_ui(c0,0)==0){
            mpz_set_ui(*inv,0);
            mpz_set_ui(*co_inv,1);
            mpz_set(*gcd,p);
            return;
        }
        mpz_t t1,t2,r,tmp;
        mpz_init(t1);mpz_init(t2);mpz_init(r);mpz_init(tmp);
        mpz_mod(r,p,c0);
        gcdExtended(r,c0,&t1,&t2,gcd);
        mpz_fdiv_q(tmp,p,c0);
        mpz_mul(tmp,tmp,t1);
        mpz_sub(*inv,t2,tmp);
        mpz_set(*co_inv,t1);
        return;
    }
public:
    mpz_t h;//public key
    static ElGamal_Param param;//this static member provides seed and state for pseudo-random generator. It also provides common knowledge of p and g.
    ElGamal_Client(){
        mpz_init(x);mpz_init(h);
        mpz_urandomb(x,param.state,param.bit_length);
        mpz_mod(x,x,param.p);//randomly choose a private key in Z_{p}
        mpz_powm(h,param.g,x,param.p);//compute the corresponding public key
    }
    commitment Get_Commitment(){//commitment C(r). Please refer to the original paper, Section 4 - structure, and Section 4.1 construction - encryption
        mpz_t y;
        mpz_init(y);
        mpz_urandomb(y,param.state,param.bit_length);
        mpz_mod(y,y,param.p);//randomly choose y in Z_{p}
        commitment ret;
        mpz_set(ret.rand,y);//use y as the commitment
        return ret;
    }
    /*ElGamal encryption of message msg with randomness (commitment) y and receiver rcvr's public key*/
    cipher_text Encrypt(mpz_t& msg, commitment& y, ElGamal_Client& rcvr){
        mpz_t c0,c1;
        mpz_init(c0);mpz_init(c1);
        mpz_powm(c0,param.g,y.rand,param.p);// c0 = g^Y (mod p)
        mpz_powm(c1,rcvr.h,y.rand,param.p);
        mpz_mul(c1,c1,msg);
        mpz_mod(c1,c1,param.p);// c1 = h^Y * msg (mod p) (h = g^X)
        cipher_text c;
        mpz_set(c.c0,c0);
        mpz_set(c.c1,c1);
        return c;
    }
    /*ElGamal Decryption: decrypt cipher text: c with externally provided public key: key*/
    plain_text Decrypt(cipher_text& c,mpz_t& key){
        mpz_t c0,c1;
        mpz_init(c0);mpz_init(c1);
        mpz_set(c0,c.c0);
        mpz_set(c1,c.c1);
        mpz_powm(c0,c0,key,param.p);//compute h^X = g^(XY)
        mpz_t t1,t2,t3;
        mpz_init(t1);mpz_init(t2);mpz_init(t3);
        gcdExtended(c0,param.p,&t1,&t2,&t3);//compute the inverse of g^(XY): t1 = (g^(XY))^(-1)
        mpz_mod(t1,t1,param.p);
        plain_text pt;
        mpz_mul(pt.msg,c1,t1);
        /*recover the message:
        c1 = msg * g^(XY). t1 = (g^(XY))^(-1). c1 * t1 = msg
        */
        mpz_mod(pt.msg,pt.msg,param.p);
        return pt;
    }
    /*ElGamal Decryption: decrypt cipher text: c with the client's own public key*/
    plain_text Decrypt(cipher_text& c){
        plain_text pt=Decrypt(c,x);
        return pt;
    }
};
/*cipher text for Functional Encryption*/
class cipher_text_FE{
public:
    mpz_t c0;//Ct_{0}
    mpz_t* c1;//Ct_{1}
    cipher_text_FE(unsigned int len){
        mpz_init(c0);
        c1=(mpz_t *) malloc(len * sizeof(mpz_t));
        for(int i=0;i<len;i++){
            mpz_init(c1[i]);
        }
    }
};
/*Secret key for Functional Encryption*/
class secret_key_FE{
public:
    mpz_t sk_y;
    secret_key_FE(){
        mpz_init(sk_y);
    }
};

/*Inner Product - DDH functional encryption is built on top of ElGamal (or other Public Key Encryption (PKE) schemes)
the class member, PKE_functionality provides common configurations (p, g) and general PKE (ElGamal) functionalities (commitment, PKE encryption and PKE decryption)
the class member, key_gen, creates a number of ElGamal clients, so that they can generate independent (secret key, public key) pairs
*/

class FE_inner_product_DDH{
private:
    unsigned int vec_len=6;//this is l in the original paper. It specifies the number of (sk,pk) pairs and the number of msg blocks
    ElGamal_Client PKE_functionality;//provide ElGamal configuration and functionalities
    secret_key_FE sk;//store the secret key sk_{y} derived from master secret key msk
    void g_x(mpz_t* x, mpz_t* gx){//according to the paper, messages: msg are encoded as g^(msg). This function converts an array of msg to the form of g^(msg)
        for(int i=0;i<vec_len;i++){
            mpz_powm(gx[i],PKE_functionality.param.g,x[i],PKE_functionality.param.p);
        }
    }
public:
    ElGamal_Client* key_gen;//a number of ElGamal clients to be initialized
    mpz_t *y;//the vector y used in KeyDer (Key Derivation)
    //initialization with default vec_len=6
    FE_inner_product_DDH(){
        /*create ElGamal Clients. Each client generates its (sk,pk) pair.
        The key generation process is implemented in the constructor of ElGamal_Client,
        so that we don't have to do anything explicitly here for Setup. 
        */
        key_gen=new ElGamal_Client[vec_len];
        //initialize the vector y so that it is ready to be used in KeyDer.
        y=(mpz_t *) malloc(vec_len * sizeof(mpz_t));
        for(int i=0;i<vec_len;i++){
            mpz_init(y[i]);
        }
    }
    //initialization with customer defined vec_len=len
    FE_inner_product_DDH(unsigned int len){
        vec_len=len;
        key_gen=new ElGamal_Client[vec_len];
        y=(mpz_t *) malloc(vec_len * sizeof(mpz_t));
        for(int i=0;i<vec_len;i++){
            mpz_init(y[i]);
        }
    }
    /*This is the implementation of KeyDer in the paper
    input: vector y output:sk_{y}
    */
    void Key_Derivation(mpz_t* vec){
        for(int i=0;i<vec_len;i++){//copy vec to y
            mpz_set(y[i],vec[i]);
        }
        mpz_set_ui(sk.sk_y,0);//clear the secret key sk_{y}
        mpz_t tmp;//store the intermediate result of Sum (y_{i} * sk_{i})
        mpz_init(tmp);
        for(int i=0;i<vec_len;i++){
            mpz_mul(tmp,y[i],key_gen[i].x);//y_{i} * sk_{i}. sk_{i} is the i-th ElGamal client's secret key sk
            mpz_add(sk.sk_y,sk.sk_y,tmp);//compute the partial sum
        }
        //obtain secret key sk_{y} and finish KeyDer
        gmp_printf("key derivation: %Zd\n", sk.sk_y);
    }
    //functional encryption's encryption functionality
    cipher_text_FE Encrypt(mpz_t* msg){
        //use PKE to get commitment C(r)
        commitment y=PKE_functionality.Get_Commitment();
        gmp_printf("Commitment Y:= %Zd\n",y.rand);
        //create the cipher text Ct=(Ct_{0}, Ct_{1}) where Ct_{1} has vec_len components
        cipher_text_FE ct(vec_len);
        mpz_t c0;
        mpz_init(c0);
        mpz_powm(c0,PKE_functionality.param.g,y.rand,PKE_functionality.param.p);//Ct_{0} = g^Y
        mpz_set(ct.c0,c0);
        mpz_t* g_msg=(mpz_t*)malloc(vec_len*sizeof(mpz_t));
        for(int i=0;i<vec_len;i++){
            mpz_init(g_msg[i]);
        }
        g_x(msg,g_msg);//convert msg to the form of g^(msg)
        for(int i=0;i<vec_len;i++){
            gmp_printf("g^x%d: %Zd\n",i+1,g_msg[i]);
            /*use commitment y, and each client key_gen[i]'s public key to encrypt g^{msg[i]}
            and obtain the i-th component of Ct_{1}
            */
            cipher_text c=PKE_functionality.Encrypt(g_msg[i],y,key_gen[i]);
            mpz_set(ct.c1[i],c.c1);
        }
        return ct;
    }
    //functional encryption's decryption functionality
    plain_text Decrypt(cipher_text_FE& ct,secret_key_FE& sk){
        mpz_t c1;
        mpz_init(c1);
        mpz_set_ui(c1,1);
        mpz_t tmp;
        mpz_init(tmp);
        for(int i=0;i<vec_len;i++){
            //raise each Ct_{i} to the power of y_{i} and compute the product of (Ct_{i})^(y_{i})
            mpz_powm(tmp,ct.c1[i],y[i],PKE_functionality.param.p);
            mpz_mul(c1,c1,tmp);
            mpz_mod(c1,c1,PKE_functionality.param.p);
        }
        cipher_text ct_pke;
        mpz_set(ct_pke.c0,ct.c0);
        mpz_set(ct_pke.c1,c1);
        gmp_printf("Decryption: c0: %Zd\n",ct_pke.c0);
        gmp_printf("Decryption: c1: %Zd\n",ct_pke.c1);
        gmp_printf("Decryption: sk_y: %Zd\n",sk.sk_y);
        //Functional encryption's decryption is to use ElGamal to decrypt (Ct_{0}, Product of (Ct_{i})^(y_{i})) with the key sk_{y}
        plain_text pt=PKE_functionality.Decrypt(ct_pke,sk.sk_y);
        return pt;
    }
    //if secret key is not specified, decryption with its own secret key sk_{y}
    plain_text Decrypt(cipher_text_FE& ct){
        plain_text pt=Decrypt(ct,sk);
        return pt;
    }
    //For each i, display (pk_{i}, sk_{i})
    void Info(){
        for(int i=0;i<vec_len;i++){
            gmp_printf("client %d \'s public key: %Zd\n",i+1,key_gen[i].h);
            gmp_printf("client %d \'s private key: %Zd\n",i+1,key_gen[i].x);
            mpz_t t;mpz_init(t);
            mpz_powm(t,key_gen[i].param.g,key_gen[i].x,key_gen[i].param.p);
            //gmp_printf("testing public key: %Zd\n",t);
            if(mpz_cmp(t,key_gen[i].h)!=0){
                printf("Error: %d\n",i+1);
            }
        }
    }
};

//generate p, g for ElGamal before everything else
ElGamal_Param ElGamal_Client::param;

int main(){
    unsigned int num_clients=2;
    //setup functional encryption with l=2
    FE_inner_product_DDH d(num_clients);
    //display (sk_{i}, pk_{i}) for i=1,2
    d.Info();
    mpz_t* vec=(mpz_t *) malloc(num_clients * sizeof(mpz_t));//vector y with l components
    mpz_t* msg=(mpz_t *) malloc(num_clients * sizeof(mpz_t));//message msg with l components
    for(int i=0;i<num_clients;i++){
        mpz_init(vec[i]);mpz_init(msg[i]);
    }
    srand((unsigned) time(NULL));
    for(int i=0;i<num_clients;i++){//both vector y and message msg are randomly initialized
        mpz_set_ui(vec[i],rand()%7+1);
        mpz_set_ui(msg[i],rand()%72+1);
    }
    for(int i=0;i<num_clients;i++){
        gmp_printf("message x%d: %Zd\n",i+1,msg[i]);
    }
    for(int i=0;i<num_clients;i++){
        gmp_printf("weight y%d: %Zd\n",i+1,vec[i]);
    }
    //KeyDer: generate sk_{y} from vector y
    d.Key_Derivation(vec);
    //Functional encryption's encryption
    cipher_text_FE ct=d.Encrypt(msg);
    gmp_printf("Encryption: c0: %Zd\n", ct.c0);
    for(int i=0;i<num_clients;i++){
        gmp_printf("Encryption: c%d: %Zd\n", i+1,ct.c1[i]);
    }
    //Functional encryption's decryption
    plain_text pt=d.Decrypt(ct);
    gmp_printf("Decrypted message: %Zd\n", pt.msg);
    //compute desired result: g^{Sum msg[i] * vec[i]}, compare with the decrypted result
    mpz_t result,tmp;
    mpz_init(result);mpz_init(tmp);
    mpz_set_ui(result,0);
    for(int i=0;i<num_clients;i++){
        mpz_mul(tmp,vec[i],msg[i]);
        mpz_add(result,result,tmp);
    }
    mpz_powm(result,ElGamal_Client::param.g,result,ElGamal_Client::param.p);
    gmp_printf("Desired result: %Zd\n", result);
    /*Test Code for ElGamal*/

    /*d.Info();
    gmp_printf("%Zd\n",d.key_gen->param.p);
    gmp_printf("%Zd\n",d.key_gen->param.g);
    mpz_t * a;
    d.Encrypt(a);*/
    /*ElGamal_Client c,d;
    gmp_printf("%Zd\n",c.param.p);
    gmp_printf("%Zd\n",c.param.g);
    gmp_printf("%Zd\n",c.h);
    gmp_printf("%Zd\n",d.param.p);
    gmp_printf("%Zd\n",d.param.g);
    gmp_printf("%Zd\n",d.h);
    mpz_t msg;
    mpz_init(msg);
    char c_msg[]="2345678901";
    mpz_set_str(msg,c_msg,10);
    cipher_text ct=c.Encrypt(msg,d);
    gmp_printf("%Zd %Zd\n",ct.c0, ct.c1);
    plain_text pt=d.Decrypt(ct);
    gmp_printf("%Zd\n",pt.msg);*/
    return 0;
}