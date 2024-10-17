

#include <mpc/lsic.hh>
#include <mpc/private_comparison.hh>
#include <mpc/enc_comparison.hh>
#include <mpc/rev_enc_comparison.hh>
#include <mpc/linear_enc_argmax.hh>

#include <classifiers/linear_classifier.hh>

#include <protobuf/protobuf_conversion.hh>
#include <net/message_io.hh>
#include <util/util.hh>


Linear_Classifier_Server::Linear_Classifier_Server(gmp_randstate_t state, unsigned int keysize, unsigned int lambda, const vector<mpz_class> &model, size_t bit_size)
: Server(state, Linear_Classifier_Server::key_deps_descriptor(), keysize, lambda), enc_model_(model.size()), bit_size_(bit_size)
{
    for (size_t i = 0; i < enc_model_.size(); i++) {
        enc_model_[i] = paillier_->encrypt(model[i]);
    }
}

Server_session* Linear_Classifier_Server::create_new_server_session(tcp::socket &socket)
{
    return new Linear_Classifier_Server_session(this, rand_state_, n_clients_++, socket);
}

void Linear_Classifier_Server_session::run_session()
{
    try {
        exchange_keys();
        
        ScopedTimer *t;
        RESET_BYTE_COUNT
        RESET_BENCHMARK_TIMER

        t = new ScopedTimer("Server: Compute dot product");
        help_compute_dot_product(linear_server_->enc_model(),true);
        delete t;
        
        t = new ScopedTimer("Server: Compare enc data");
        help_enc_comparison(linear_server_->bit_size(), GC_PROTOCOL);
        delete t;

#ifdef BENCHMARK
        cout << "Benchmark: " << GET_BENCHMARK_TIME << " ms" << endl;
        cout << IOBenchmark::byte_count() << " exchanged bytes" << endl;
        cout << IOBenchmark::interaction_count() << " interactions" << endl;
#endif

    } catch (std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
    
    delete this;
}


Linear_Classifier_Client::Linear_Classifier_Client(boost::asio::io_service& io_service, gmp_randstate_t state, unsigned int keysize, unsigned int lambda, const vector<mpz_class> &vals, size_t bit_size)
: Client(io_service,state,Linear_Classifier_Server::key_deps_descriptor(),keysize,lambda), bit_size_(bit_size),values_(vals)
{
    
}

bool Linear_Classifier_Client::run()
{
    // get public keys
    RESET_BYTE_COUNT
    exchange_keys();
#ifdef BENCHMARK
    const double to_kB = 1 << 10;
    cout << "Key exchange: " <<  (IOBenchmark::byte_count()/to_kB) << " kB" << endl;
    cout << IOBenchmark::interaction_count() << " interactions" << endl;
#endif
    
    ScopedTimer *t;
    RESET_BYTE_COUNT
    RESET_BENCHMARK_TIMER
    // prepare data
    vector <mpz_class> x = values_;
    x.push_back(-1);
    
    t = new ScopedTimer("Client: Compute dot product");
    // compute the dot product
    mpz_class v = compute_dot_product(x);
    mpz_class w = 1; // encryption of 0
    delete t;

    t = new ScopedTimer("Client: Compare enc data");
    // build the comparator over encrypted data
    bool result = enc_comparison(v,w,bit_size_,GC_PROTOCOL);
    delete t;
#ifdef BENCHMARK
    cout << "Benchmark: " << GET_BENCHMARK_TIME << " ms" << endl;
    cout << (IOBenchmark::byte_count()/to_kB) << " exchanged kB" << endl;
    cout << IOBenchmark::interaction_count() << " interactions" << endl;
#endif
    return result;
}


Bench_Linear_Classifier_Server::Bench_Linear_Classifier_Server(gmp_randstate_t state, unsigned int keysize, unsigned int lambda, const vector<mpz_class> &model, size_t bit_size, unsigned int nRounds)
: Server(state, Linear_Classifier_Server::key_deps_descriptor(), keysize, lambda), enc_model_(model.size()), bit_size_(bit_size), nRounds_(nRounds)
{
    for (size_t i = 0; i < enc_model_.size(); i++) {
        enc_model_[i] = paillier_->encrypt(model[i]);
    }
}

Server_session* Bench_Linear_Classifier_Server::create_new_server_session(tcp::socket &socket)
{
    return new Bench_Linear_Classifier_Server_session(this, rand_state_, n_clients_++, socket);
}

void Bench_Linear_Classifier_Server_session::run_session()
{
    try {
        exchange_keys();
        
        double server_time = 0.;
        unsigned int nRounds = linear_server_->nRounds();
        for (unsigned int i = 0; i < nRounds; i++) {
            RESET_BENCHMARK_TIMER
            
            help_compute_dot_product(linear_server_->enc_model(),true);
            
            help_enc_comparison(linear_server_->bit_size(), GC_PROTOCOL);
            
            server_time += GET_BENCHMARK_TIME;
//            cout << "Round #" << i << " done" << endl;
        }
#ifdef BENCHMARK
        cout << "Average time for " << nRounds << " rounds: " << endl;
        cout << "Server time: " << server_time/nRounds << endl;
#endif

    } catch (std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
    
    delete this;
}


Bench_Linear_Classifier_Client::Bench_Linear_Classifier_Client(boost::asio::io_service& io_service, gmp_randstate_t state, unsigned int keysize, unsigned int lambda, const vector<mpz_class> &vals, size_t bit_size, unsigned int nRounds)
: Client(io_service,state,Linear_Classifier_Server::key_deps_descriptor(),keysize,lambda), bit_size_(bit_size),values_(vals), nRounds_(nRounds)
{
    
}

void Bench_Linear_Classifier_Client::run()
{
    // get public keys
    RESET_BYTE_COUNT
    exchange_keys();
#ifdef BENCHMARK
    const double to_kB = 1 << 10;
    cout << "Key exchange: " <<  (IOBenchmark::byte_count()/to_kB) << " kB" << endl;
    cout << IOBenchmark::interaction_count() << " interactions" << endl;
#endif
    bool firstResult;
    double compare_time = 0., dot_prod_time = 0., client_time = 0.;
    Timer t;

    RESET_BYTE_COUNT
    mpz_class v,w;
    for (unsigned int i = 0; i < nRounds_; i++) {

        RESET_BENCHMARK_TIMER
        // prepare data
        vector <mpz_class> x = values_;
        x.push_back(-1);

        t.lap(); // reset timer
        
        // compute the dot product
        v = compute_dot_product(x);
        w = 1; // encryption of 0
        
        dot_prod_time += t.lap_ms();
        // build the comparator over encrypted data
        bool result = enc_comparison(v,w,bit_size_,GC_PROTOCOL);
        compare_time += t.lap_ms();

        client_time += GET_BENCHMARK_TIME;

        if (i == 0) {
            firstResult = result;
        }else{
            assert(firstResult == result);
        }

//        cout << "Round #" << i << " done" << endl;

    }
#ifdef BENCHMARK
    cout << "Average time for " << nRounds_ << " rounds: " << endl;
    cout << "Client time: " << client_time/nRounds_ << endl;
    cout << "Compare time: " << compare_time/nRounds_ << endl;
    cout << "Dot product time: " << dot_prod_time/nRounds_ << endl;
    cout << (IOBenchmark::byte_count()/(to_kB*nRounds_)) << " exchanged kB per round" << endl;
    cout << IOBenchmark::interaction_count()/nRounds_ << " interactions per round" << endl;
#endif

/* mpz_class c_a[5],c_b[5];
double L_bits[5];
int nbits = 64;
for(unsigned int i=0; i<5; i++){
    gmp_randstate_t randstate;
    gmp_randinit_default(randstate);
    gmp_randseed_ui(randstate,time(NULL));
    mpz_class a, b;
    mpz_urandom_len(a.get_mpz_t(), randstate, nbits);
    mpz_urandom_len(b.get_mpz_t(), randstate, nbits);
    cout<<"a : "<<a<<"b : "<<b<<endl;
    c_a[i] = server_paillier_->encrypt(a);
    c_b[i] = server_paillier_->encrypt(b);
    L_bits[i] = nbits;
    nbits = 2*nbits;
    cout<<"nbits : "<<nbits<<endl;
}
double Ctime[5];
ScopedTimer *t1;
for(unsigned int i=0; i<5; i++){
    RESET_BENCHMARK_TIMER
    RESET_BYTE_COUNT
    client_time=0.0;
    
    t1 = new ScopedTimer("client: Compare");
    bool result = enc_comparison(c_a[i],c_b[i],L_bits[i],GC_PROTOCOL);
    delete t1;
    
    client_time+=GET_BENCHMARK_TIME;
    // write to an array then to the 'txt' file
    Ctime[i] = client_time;
#ifdef BENCHMARK
    cout << "Client time: " << client_time << endl;
    cout << IOBenchmark::byte_count()/to_kB<< " exchanged kB per round" << endl;
    cout << IOBenchmark::interaction_count()<< " interactions per round" << endl;
#endif
}
    writeToFile(Ctime,L_bits,5);
	 */
   
}

void Bench_Linear_Classifier_Client::writeToFile(double a[],double b[],size_t size){
   ofstream outfile("client_64_t_1024.txt", std::ios::app);
   if (!outfile)
   {
       cout<<"Can't find the file !"<<endl;
   }
   for (size_t i = 0; i < size; i++)
   {
	outfile << a[i] <<" "<<b[i]<< endl;
   }
   outfile.close();
}
