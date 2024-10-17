#include <net/exec_protocol.hh>

#include <protobuf/protobuf_conversion.hh>
#include <net/net_utils.hh>

#include <mpc/change_encryption_scheme.hh>
#include <thread>
#include <net/defs.hh>

#include <net/oblivious_transfer.hh>

void exec_comparison_protocol_A(tcp::socket &socket, Comparison_protocol_A *comparator, unsigned int n_threads)
{
    if(typeid(*comparator) == typeid(LSIC_A)) {
        exec_lsic_A(socket, reinterpret_cast<LSIC_A*>(comparator));
    }else if(typeid(*comparator) == typeid(Compare_A)){
        exec_priv_compare_A(socket, reinterpret_cast<Compare_A*>(comparator),n_threads);
    }else if(typeid(*comparator) == typeid(GC_Compare_A)) {
        exec_garbled_compare_A(socket, reinterpret_cast<GC_Compare_A*>(comparator));
    }
}

void exec_lsic_A(tcp::socket &socket, LSIC_A *lsic)
{
    LSIC_Packet_A a_packet;
    LSIC_Packet_B b_packet;
    Protobuf::LSIC_A_Message a_message;
    Protobuf::LSIC_B_Message b_message;
    
    bool state;
   
    // response-request
    for (; ; ) {
        b_message = readMessageFromSocket<Protobuf::LSIC_B_Message>(socket);
        b_packet = convert_from_message(b_message);
        
        state = lsic->answerRound(b_packet,&a_packet);
        
        if (state) {
            return;
        }
        
        a_message = convert_to_message(a_packet);
        sendMessageToSocket(socket, a_message);
    }
}

void exec_priv_compare_A(tcp::socket &socket, Compare_A *comparator, unsigned int n_threads)
{
    vector<mpz_class> c_b(comparator->bit_length());
    
    // first get encrypted bits
    
    Protobuf::BigIntArray c_b_message = readMessageFromSocket<Protobuf::BigIntArray>(socket);
    c_b = convert_from_message(c_b_message);

    vector<mpz_class> c_rand = comparator->compute(c_b,n_threads);
    
    // send the result
    
    Protobuf::BigIntArray c_rand_message = convert_to_message(c_rand);
    sendMessageToSocket(socket, c_rand_message);
    
    // wait for the encrypted result
    mpz_class c_t_prime;
    
    Protobuf::BigInt c_t_prime_message = readMessageFromSocket<Protobuf::BigInt>(socket);
    c_t_prime = convert_from_message(c_t_prime_message);
    
    comparator->unblind(c_t_prime);
}

void exec_garbled_compare_A(tcp::socket &socket, GC_Compare_A *comparator)
{
    comparator->prepare_circuit();
    int l = comparator->bit_length();
    GarbledCircuit* gc = comparator->get_garbled_circuit();
    
    block a_labels[l], b_labels[l+1];
    block global_key;
    int a_inputs[l];
    
    // first get the global key ...
    global_key = read_block_from_socket(socket);
    comparator->set_global_key(global_key);
    
    // ... and then the garbled table ...
    read_byte_string_from_socket(socket, (unsigned char*)(gc->garbledTable), sizeof(GarbledTable)*(gc->q));
    
    // ... b's labels
    read_byte_string_from_socket(socket, (unsigned char*)b_labels, (l+1)*sizeof(block));
    
    // initiate OT to get our labels
    
    vector<bool> a_bits = comparator->get_a_bits();
    for (size_t i = 0; i < l; i++) {
        a_inputs[i] = a_bits[i];
    }

    ObliviousTransfer::receiver(l, a_inputs, (char *)a_labels, socket, sizeof(block));
    
    // evaluate GC
    
    comparator->evaluateGC(a_labels, b_labels);
    
    
    // get the outputmap
    OutputMap om = new block[2*sizeof(block)]; // m = 1
    read_byte_string_from_socket(socket, (unsigned char*)om, 2*sizeof(block));

    // apply the outputmap
    comparator->map_output(om);
    
    // unblind
    Protobuf::BigInt mask_m = readMessageFromSocket<Protobuf::BigInt>(socket);
    mpz_class mask = convert_from_message(mask_m);
    comparator->unblind(mask);
}

void exec_comparison_protocol_B(tcp::socket &socket, Comparison_protocol_B *comparator, unsigned int n_threads)
{
    if(typeid(*comparator) == typeid(LSIC_B)) {
        exec_lsic_B(socket, reinterpret_cast<LSIC_B*>(comparator));
    }else if(typeid(*comparator) == typeid(Compare_B)){
        exec_priv_compare_B(socket, reinterpret_cast<Compare_B*>(comparator), n_threads);
    }else if(typeid(*comparator) == typeid(GC_Compare_B)) {
        exec_garbled_compare_B(socket, reinterpret_cast<GC_Compare_B*>(comparator));
    }
}

void exec_lsic_B(tcp::socket &socket, LSIC_B *lsic)
{
//    cout << "Start LSIC B" << endl;

    LSIC_Packet_A a_packet;
    LSIC_Packet_B b_packet = lsic->setupRound();
    Protobuf::LSIC_A_Message a_message;
    Protobuf::LSIC_B_Message b_message;
    
    b_message = convert_to_message(b_packet);
    sendMessageToSocket(socket, b_message);
    
//    cout << "LSIC setup sent" << endl;
    
    // wait for packets
    
    for (;b_packet.index < lsic->bitLength()-1; ) {
        a_message = readMessageFromSocket<Protobuf::LSIC_A_Message>(socket);
        a_packet = convert_from_message(a_message);
        
        b_packet = lsic->answerRound(a_packet);
        
        b_message = convert_to_message(b_packet);
        sendMessageToSocket(socket, b_message);
    }
    
//    cout << "LSIC B Done" << endl;
}

void exec_priv_compare_B(tcp::socket &socket, Compare_B *comparator, unsigned int n_threads)
{
    vector<mpz_class> c(comparator->bit_length());
    
    
    // send the encrypted bits
    Protobuf::BigIntArray c_b_message = convert_to_message(comparator->encrypt_bits_parallel(n_threads));
    sendMessageToSocket(socket, c_b_message);
    
    // wait for the answer from the client
    Protobuf::BigIntArray c_message = readMessageFromSocket<Protobuf::BigIntArray>(socket);
    c = convert_from_message(c_message);
    
    
    //    input_stream >> c;
    
    mpz_class c_t_prime = comparator->search_zero(c);
    
    // send the blinded result
    Protobuf::BigInt c_t_prime_message = convert_to_message(c_t_prime);
    sendMessageToSocket(socket, c_t_prime_message);
    
}

void exec_garbled_compare_B(tcp::socket &socket, GC_Compare_B *comparator)
{
    comparator->prepare_circuit();
    int l = comparator->bit_length();
    GarbledCircuit* gc = comparator->get_garbled_circuit();
    
    block global_key;
    
    // first send the global key ...
    global_key = comparator->get_global_key();
    write_block_to_socket(global_key, socket);
    
    // ... and then the garbled table ...
    write_byte_string_to_socket(socket, (unsigned char*)(gc->garbledTable), sizeof(GarbledTable)*(gc->q));
    
    // ... b's labels
    block *b_labels = comparator->get_b_input_labels();
    write_byte_string_to_socket(socket, (unsigned char*)b_labels, (l+1)*sizeof(block));
    
    // initiate OT send get a's labels
    
    block *all_a_labels;
    all_a_labels = comparator->get_all_a_input_labels();
    
    ObliviousTransfer::sender(l,(char *)all_a_labels, socket, sizeof(block));
    
    
    // send the outputmap
    OutputMap om = comparator->get_output_map(); // m = 1
    write_byte_string_to_socket(socket, (unsigned char*)om, 2*sizeof(block));
    
    // send the mask
    mpz_class mask = comparator->get_enc_mask();
    Protobuf::BigInt mask_m = convert_to_message(mask);
    sendMessageToSocket(socket, mask_m);
}

void exec_rev_enc_comparison_owner(tcp::socket &socket, Rev_EncCompare_Owner &owner, unsigned int lambda, bool decrypt_result, unsigned int n_threads)
{
    size_t l = owner.bit_length();
    mpz_class c_z(owner.setup(lambda));
    
    Protobuf::Enc_Compare_Setup_Message setup_message = convert_to_message(c_z,l);
    sendMessageToSocket(socket, setup_message);
    
    // the other party does some computation, we just have to run the comparator
    
    exec_comparison_protocol_A(socket, owner.comparator(), n_threads);
    
    Protobuf::BigInt c_z_l_message = readMessageFromSocket<Protobuf::BigInt>(socket);
    mpz_class c_z_l = convert_from_message(c_z_l_message);
    
    
    mpz_class c_t = owner.concludeProtocol(c_z_l);
    
    // if we don't decrypt the result, we are done now ...
    if (!decrypt_result) {
        return;
    }
    // ... else send the last message to the server
    Protobuf::BigInt c_t_message = convert_to_message(c_t);
    sendMessageToSocket(socket, c_t_message);
}

void exec_rev_enc_comparison_helper(tcp::socket &socket, Rev_EncCompare_Helper &helper, bool decrypt_result, unsigned int n_threads)
{
    // setup the helper if necessary
    if (!helper.is_set_up()) {
        Protobuf::Enc_Compare_Setup_Message setup_message = readMessageFromSocket<Protobuf::Enc_Compare_Setup_Message>(socket);
        if (setup_message.has_bit_length()) {
            helper.set_bit_length(setup_message.bit_length());
        }
        mpz_class c_z = convert_from_message(setup_message);
        
        helper.setup(c_z);
    }
    
    // now, we need to run the comparison protocol
    exec_comparison_protocol_B(socket, helper.comparator(), n_threads);
    
    
    mpz_class c_z_l(helper.get_c_z_l());
    
    Protobuf::BigInt c_z_l_message = convert_to_message(c_z_l);
    sendMessageToSocket(socket, c_z_l_message);
    
    // if we don't decrypt the result, we are done now ...
    if (!decrypt_result) {
        return;
    }

    // ... else wait for the answer of the owner
    Protobuf::BigInt c_t_message = readMessageFromSocket<Protobuf::BigInt>(socket);
    mpz_class c_t = convert_from_message(c_t_message);
    helper.decryptResult(c_t);
}

void exec_enc_comparison_owner(tcp::socket &socket, EncCompare_Owner &owner, unsigned int lambda, bool decrypt_result, unsigned int n_threads)
{
    // now run the protocol itself
    size_t l = owner.bit_length();
    mpz_class c_z(owner.setup(lambda));
    
    Protobuf::Enc_Compare_Setup_Message setup_message = convert_to_message(c_z,l);
    sendMessageToSocket(socket, setup_message);
    
    // the server does some computation, we just have to run the lsic
    
    exec_comparison_protocol_B(socket, owner.comparator(), n_threads);
    
    mpz_class c_r_l(owner.get_c_r_l());
    Protobuf::BigInt c_r_l_message = convert_to_message(c_r_l);
    sendMessageToSocket(socket, c_r_l_message);
    
    // if we don't decrypt the result, we are done now ...
    if (!decrypt_result) {
        return;
    }
    // ... else wait for the answer of the owner
    Protobuf::BigInt c_t_message = readMessageFromSocket<Protobuf::BigInt>(socket);
    mpz_class c_t = convert_from_message(c_t_message);
    
    owner.decryptResult(c_t);
}

void exec_enc_comparison_helper(tcp::socket &socket, EncCompare_Helper &helper, bool decrypt_result, unsigned int n_threads)
{
    // setup the helper if necessary
    if (!helper.is_set_up()) {
        Protobuf::Enc_Compare_Setup_Message setup_message = readMessageFromSocket<Protobuf::Enc_Compare_Setup_Message>(socket);
        if (setup_message.has_bit_length()) {
            helper.set_bit_length(setup_message.bit_length());
        }
        mpz_class c_z = convert_from_message(setup_message);
        
        helper.setup(c_z);
    }
    
    // now, we need to run the comparison protocol
    exec_comparison_protocol_A(socket, helper.comparator(), n_threads);
    
    Protobuf::BigInt c_r_l_message = readMessageFromSocket<Protobuf::BigInt>(socket);
    mpz_class c_r_l = convert_from_message(c_r_l_message);
    
    mpz_class c_t = helper.concludeProtocol(c_r_l);
    
    // if we don't decrypt the result, we are done now ...
    if (!decrypt_result) {
        return;
    }
    // else ... send the last message to the server
    Protobuf::BigInt c_t_message = convert_to_message(c_t);
    sendMessageToSocket(socket, c_t_message);
}


void multiple_exec_enc_comparison_owner_thread_call(shared_ptr<tcp::socket> socket, EncCompare_Owner *owner_ptr, unsigned int lambda, bool decrypt_result, unsigned int n_threads)
{
    exec_enc_comparison_owner(*socket,*owner_ptr,lambda,decrypt_result,n_threads);
}

void multiple_exec_enc_comparison_owner(tcp::socket &socket, vector<EncCompare_Owner*> &owners, unsigned int lambda, bool decrypt_result, unsigned int n_threads)
{
    // when doing multiple executions in parallel, the owner creates the sockets and the helper connects
    
    thread **comparison_threads = new thread* [owners.size()];
    
    tcp::endpoint endpoint = socket.local_endpoint(); // (tcp::v4(), PORT+1);
    endpoint.port(PORT+1);
    
    tcp::acceptor acceptor(socket.get_io_service(), endpoint);
    
    for (size_t i = 0; i < owners.size(); i++) {
        shared_ptr<tcp::socket> comp_socket (new tcp::socket(socket.get_io_service()));
        
        if (i == 0) {
            // now that we are ready to accept connexions on this port, notify the client
            sendMessageToSocket<Protobuf::SOCKET_READY_Message>(socket,Protobuf::SOCKET_READY_Message());
        }
        
        acceptor.accept(*comp_socket);
        
        // the socket has been created and the helper connected, now run the comparisons
        comparison_threads[i] = new thread(&multiple_exec_enc_comparison_owner_thread_call,comp_socket,owners[i],lambda,decrypt_result,n_threads);
    }
    
    for (size_t i = 0 ; i < owners.size(); i++) {
        comparison_threads[i]->join();
        delete comparison_threads[i];
    }
    
    delete [] comparison_threads;
}

void multiple_exec_enc_comparison_helper_thread_call(shared_ptr<tcp::socket> socket,EncCompare_Helper *helper_ptr, bool decrypt_result, unsigned int n_threads)
{
    exec_enc_comparison_helper(*socket,*helper_ptr,decrypt_result,n_threads);
}

void multiple_exec_enc_comparison_helper(tcp::socket &socket, vector<EncCompare_Helper*> &helpers, bool decrypt_result, unsigned int n_threads)
{
    thread **comparison_threads = new thread* [helpers.size()];
    
    tcp::resolver resolver(socket.get_io_service());
    tcp::endpoint endpoint = socket.remote_endpoint(); // (tcp::v4(), PORT+1);
    endpoint.port(PORT+1);
    
    
    // wait for the owner to be ready
    readMessageFromSocket<Protobuf::SOCKET_READY_Message>(socket);
    
    for (size_t i = 0; i < helpers.size(); i++) {
        shared_ptr<tcp::socket> comp_socket (new tcp::socket(socket.get_io_service()));
        comp_socket->connect(endpoint);
        
        // the socket has been created and the owner connected, now run the comparisons
        comparison_threads[i] = new thread(&multiple_exec_enc_comparison_helper_thread_call,(comp_socket),(helpers[i]),decrypt_result,n_threads);
    }
    
    for (size_t i = 0 ; i < helpers.size(); i++) {
        comparison_threads[i]->join();
        delete comparison_threads[i];
    }
    
    delete [] comparison_threads;
}

void multiple_exec_rev_enc_comparison_owner_thread_call(shared_ptr<tcp::socket> socket, Rev_EncCompare_Owner *owner_ptr, unsigned int lambda, bool decrypt_result, unsigned int n_threads)
{
    exec_rev_enc_comparison_owner(*socket,*owner_ptr,lambda,decrypt_result,n_threads);
}

void multiple_exec_rev_enc_comparison_owner(tcp::socket &socket, vector<Rev_EncCompare_Owner*> &owners, unsigned int lambda, bool decrypt_result, unsigned int n_threads)
{
    // when doing multiple executions in parallel, the owner creates the sockets and the helper connects
    
    thread **comparison_threads = new thread* [owners.size()];
    
    tcp::endpoint endpoint = socket.local_endpoint(); // (tcp::v4(), PORT+1);
    endpoint.port(PORT+1);
    
    tcp::acceptor acceptor(socket.get_io_service(), endpoint);
    
    for (size_t i = 0; i < owners.size(); i++) {
        shared_ptr<tcp::socket> comp_socket (new tcp::socket(socket.get_io_service()));
        
        if (i == 0) {
            // now that we are ready to accept connexions on this port, notify the client
            sendMessageToSocket<Protobuf::SOCKET_READY_Message>(socket,Protobuf::SOCKET_READY_Message());
        }
        
        acceptor.accept(*comp_socket);
        
        // the socket has been created and the helper connected, now run the comparisons
        comparison_threads[i] = new thread(&multiple_exec_rev_enc_comparison_owner_thread_call,comp_socket,owners[i],lambda,decrypt_result,n_threads);
    }
    
    for (size_t i = 0 ; i < owners.size(); i++) {
        comparison_threads[i]->join();
        delete comparison_threads[i];
    }
    
    delete [] comparison_threads;
}

void multiple_exec_rev_enc_comparison_helper_thread_call(shared_ptr<tcp::socket> socket,Rev_EncCompare_Helper *helper_ptr, bool decrypt_result, unsigned int n_threads)
{
    exec_rev_enc_comparison_helper(*socket,*helper_ptr,decrypt_result,n_threads);
}

void multiple_exec_rev_enc_comparison_helper(tcp::socket &socket, vector<Rev_EncCompare_Helper*> &helpers, bool decrypt_result, unsigned int n_threads)
{
    thread **comparison_threads = new thread* [helpers.size()];
    
    tcp::resolver resolver(socket.get_io_service());
    tcp::endpoint endpoint = socket.remote_endpoint(); // (tcp::v4(), PORT+1);
    endpoint.port(PORT+1);
    
    
    // wait for the owner to be ready
    readMessageFromSocket<Protobuf::SOCKET_READY_Message>(socket);
    
    for (size_t i = 0; i < helpers.size(); i++) {
        shared_ptr<tcp::socket> comp_socket (new tcp::socket(socket.get_io_service()));
        comp_socket->connect(endpoint);
        
        // the socket has been created and the owner connected, now run the comparisons
        comparison_threads[i] = new thread(&multiple_exec_rev_enc_comparison_helper_thread_call,(comp_socket),(helpers[i]),decrypt_result,n_threads);
    }
    
    for (size_t i = 0 ; i < helpers.size(); i++) {
        comparison_threads[i]->join();
        delete comparison_threads[i];
    }
    
    delete [] comparison_threads;
}


void exec_linear_enc_argmax(tcp::socket &socket, Linear_EncArgmax_Owner &owner, function<Comparison_protocol_A*()> comparator_creator, unsigned int lambda, unsigned int n_threads)
{
    size_t k = owner.elements_number();
    for (size_t i = 0; i < (k-1); i++) {
        Comparison_protocol_A *comparator = comparator_creator();
        
        Rev_EncCompare_Owner rev_enc_owner = owner.create_current_round_rev_enc_compare_owner(comparator);
        
        exec_rev_enc_comparison_owner(socket, rev_enc_owner, lambda, true, n_threads);
        
        mpz_class randomized_enc_max, randomized_value;
        owner.next_round(randomized_enc_max, randomized_value);
        
        // send the randomizations to the server
        sendIntToSocket(socket,randomized_enc_max);
        sendIntToSocket(socket,randomized_value);
        
        // get the server's response
        mpz_class new_enc_max, x, y;
        new_enc_max = readIntFromSocket(socket);
        x = readIntFromSocket(socket);
        y = readIntFromSocket(socket);
        
        owner.update_enc_max(new_enc_max, x, y);
    }
    
    mpz_class permuted_argmax;
    permuted_argmax = readIntFromSocket(socket);
    
    owner.unpermuteResult(permuted_argmax.get_ui());
}

void exec_linear_enc_argmax(tcp::socket &socket, Linear_EncArgmax_Helper &helper, function<Comparison_protocol_B*()> comparator_creator, unsigned int n_threads)
{
    size_t k = helper.elements_number();
    
    for (size_t i = 0; i < k - 1; i++) {
        //        cout << "Round " << i << endl;
//        Compare_B comparator(0,nbits,server_->paillier(),server_->gm());
        //        LSIC_B comparator(0,nbits,server_->gm());
        Comparison_protocol_B *comparator = comparator_creator();

        Rev_EncCompare_Helper rev_enc_helper = helper.rev_enc_compare_helper(comparator);
        
        exec_rev_enc_comparison_helper(socket, rev_enc_helper, true, n_threads);
        
        mpz_class randomized_enc_max, randomized_value;
        
        // read the values sent by the client
        randomized_enc_max = readIntFromSocket(socket);
        randomized_value = readIntFromSocket(socket);
        
        // and send the server's response
        mpz_class new_enc_max, x, y;
        helper.update_argmax(rev_enc_helper.output(), randomized_enc_max, randomized_value, i+1, new_enc_max, x, y);
        
        sendIntToSocket(socket,new_enc_max);
        sendIntToSocket(socket,x);
        sendIntToSocket(socket,y);
    }
    
//    cout << "Send result" << endl;
    mpz_class permuted_argmax = helper.permuted_argmax();
    sendIntToSocket(socket, permuted_argmax);
}

void exec_tree_enc_argmax(tcp::socket &socket, Tree_EncArgmax_Owner &owner, function<Comparison_protocol_A*()> comparator_creator, unsigned int lambda, unsigned int n_threads)
{
    size_t k = owner.elements_number();
    
    while (owner.new_round_needed()) {
        vector<Rev_EncCompare_Owner*> rev_enc_owners = owner.create_current_round_rev_enc_compare_owners(comparator_creator);

        unsigned int thread_per_job = ceilf(((float)n_threads)/rev_enc_owners.size());
        multiple_exec_rev_enc_comparison_owner(socket,rev_enc_owners,lambda,true,thread_per_job);
        
        // cleanup
        for (size_t i = 0; i < rev_enc_owners.size(); i++) {
            delete rev_enc_owners[i];
        }
        
        vector<mpz_class> randomized_enc_max = owner.next_round();
        
        // send the randomized values to the helper
        send_int_array_to_socket(socket,randomized_enc_max);
        
        // get the helper's response
        vector<mpz_class> new_enc_max, x, y;
        
        new_enc_max = read_int_array_from_socket(socket);
        x = read_int_array_from_socket(socket);
        y = read_int_array_from_socket(socket);
        
        owner.update_local_max(new_enc_max, x, y);
    }
    
    mpz_class permuted_argmax;
    permuted_argmax = readIntFromSocket(socket);
    
    owner.unpermuteResult(permuted_argmax.get_ui());
}

void exec_tree_enc_argmax(tcp::socket &socket, Tree_EncArgmax_Helper &helper, function<Comparison_protocol_B*()> comparator_creator, unsigned int n_threads)
{
    size_t k = helper.elements_number();
    
    while (helper.new_round_needed()) {
        vector<Rev_EncCompare_Helper*> rev_enc_helpers = helper.create_current_round_rev_enc_compare_helpers(comparator_creator);
        
        unsigned int thread_per_job = ceilf(((float)n_threads)/rev_enc_helpers.size());
       
        multiple_exec_rev_enc_comparison_helper(socket,rev_enc_helpers,true,thread_per_job);
        
        // get result and cleanup
        vector<bool> results (rev_enc_helpers.size());
        for (size_t i = 0; i < rev_enc_helpers.size(); i++) {
            results[i] = rev_enc_helpers[i]->output();
            delete rev_enc_helpers[i];
        }
        
        // read the values sent by the owner
        vector<mpz_class> randomized_enc_max = read_int_array_from_socket(socket);
        
        
        vector<mpz_class> new_enc_max, x, y;
        
        helper.update_argmax(results, randomized_enc_max, new_enc_max, x, y);

        // and send the server's response
        send_int_array_to_socket(socket,new_enc_max);
        send_int_array_to_socket(socket,x);
        send_int_array_to_socket(socket,y);
    }
    
    // send the permuted result
    mpz_class permuted_argmax = helper.permuted_argmax();
    sendIntToSocket(socket, permuted_argmax);
}

Ctxt exec_change_encryption_scheme_slots(tcp::socket &socket, const vector<mpz_class> &c_gm, GM &gm, const FHEPubKey& publicKey, const EncryptedArray &ea, gmp_randstate_t randstate)
{
    Change_ES_FHE_to_GM_slots_A switcher;
    vector<mpz_class> c_gm_blinded = switcher.blind(c_gm,gm,randstate, ea.size());
    
    send_int_array_to_socket(socket, c_gm_blinded);
    
    Ctxt c_blinded_fhe = read_fhe_ctxt_from_socket(socket, publicKey);
    
    
    Ctxt c_fhe = switcher.unblind(c_blinded_fhe,publicKey,ea);

    return c_fhe;
}

void exec_change_encryption_scheme_slots_helper(tcp::socket &socket, GM_priv &gm, const FHEPubKey &publicKey, const EncryptedArray &ea)
{
    vector<mpz_class> c_gm_blinded = read_int_array_from_socket(socket);
    Ctxt c_blinded_fhe = Change_ES_FHE_to_GM_slots_B::decrypt_encrypt(c_gm_blinded,gm,publicKey,ea);
    
    send_fhe_ctxt_to_socket(socket, c_blinded_fhe);
}

mpz_class exec_compute_dot_product(tcp::socket &socket, const vector<mpz_class> &x, Paillier &p)
{
    // get the input vector from the socket
    vector<mpz_class> y = read_int_array_from_socket(socket);
    
    // compute the encrypted dot product
    mpz_class v = 1;
    
    for (size_t i = 0; i < y.size(); i++) {
        v = p.add(v, p.constMult(x[i],y[i]));
    }

    return v;
}

void exec_help_compute_dot_product(tcp::socket &socket, const vector<mpz_class> &y, Paillier_priv &pp, bool encrypted_input)
{
    vector<mpz_class> c_y;
    
    // encrypt the input vector if necessary
    if (encrypted_input) {
        c_y  = y;
    }else{
        c_y = vector<mpz_class>(y.size());
        
        for (size_t i = 0; i < y.size(); i++) {
            c_y[i] = pp.encrypt(y[i]);
        }
    }
    
    send_int_array_to_socket(socket, c_y);
}

//add by andy 2017
vector<mpz_class> exec_change_encryption_scheme_slots(tcp::socket &socket,const vector<Ctxt> &c_fhe,Paillier &p_k,const FHEPubKey& publicKey, const EncryptedArray &ea, gmp_randstate_t randstate)
{
     // fhe blind r to every cipher,a = a+r
     Change_ES_FHE_to_Paillier_slots_A switcher;
     vector<Ctxt> c_fhe_blinded = switcher.blind(c_fhe,publicKey,randstate, ea);
     
     // send total num of data n to server
     sendIntToSocket(socket,c_fhe_blinded.size());
     
     // send fhe_blind data to server
     for(size_t i=0;i<c_fhe_blinded.size();i++)
     {
          send_fhe_ctxt_to_socket(socket,c_fhe_blinded[i]);
     }

     vector<mpz_class> c_blinded_paillier = read_int_array_from_socket(socket);
     
     vector<mpz_class> c_paillier = switcher.unblind(c_blinded_paillier,p_k);
      

     //test true?
     //send_int_array_to_socket(socket,c_paillier);
       

     return c_paillier;
     
}

void exec_change_encryption_scheme_slots_helper(tcp::socket &socket,Paillier &p_k, const FHESecKey &secretKey,const EncryptedArray &ea)
{
     
     mpz_class n = readIntFromSocket(socket);
     const FHEPubKey& publicKey = secretKey;
     vector<Ctxt> c_fhe_blinded;
     for(size_t i=0;i<n;i++)
     {
          Ctxt c_blinded_fhe = read_fhe_ctxt_from_socket(socket,publicKey);
	  c_fhe_blinded.push_back(c_blinded_fhe);
     }
      
     vector<mpz_class> c_blinded_paillier = Change_ES_FHE_to_Paillier_slots_B::decrypt_encrypt(c_fhe_blinded,p_k,secretKey,ea);
     send_int_array_to_socket(socket,c_blinded_paillier);
}

//add end 2017

//add by andy 2018

mpz_class exec_Encrypted_LSB(tcp::socket &socket,mpz_class T,mpz_class i,mpz_class N,gmp_randstate_t rand_state_,Paillier &p)
{

        cout<<"N : "<<N<<endl;
        cout<<"T : "<<T<<endl;
    //选择随机数r
	mpz_class res,e_xi,r,b=2;
	mpz_urandomm(r.get_mpz_t(),rand_state_,N.get_mpz_t());
        cout<<"r : "<<r<<endl;
        mpz_cdiv_r (res.get_mpz_t(), r.get_mpz_t(), b.get_mpz_t());
	
        //mpz_class Y = p.add(p.encrypt(r),T);
        mpz_class e_r = p.encrypt(r);
        mpz_class Y = p.add(e_r,T);
        cout<<"Y : "<<Y<<endl;
       
        // send Y to server
        Protobuf::BigInt setup_message = convert_to_message(Y);
        sendMessageToSocket(socket, setup_message);

        //get a from server
        Protobuf::BigInt a_message = readMessageFromSocket<Protobuf::BigInt>(socket);
        mpz_class a = convert_from_message(a_message);

       
       
        cout<<"res : "<<res<<endl;
	if(res==0)
	{
	    e_xi = a;
	}else
	{
	    e_xi = p.sub(p.encrypt(1),a);
	}

        // send e_xi to server
        //setup_message = convert_to_message(e_xi);
        //sendMessageToSocket(socket, setup_message);

    	return e_xi;
}

//二进制转为10进制
mpz_class bits2mpz(vector<mpz_class> vec,int m,Paillier p)
{
	mpz_class U,t_i;
    mpz_t a;
	mpz_init_set_ui(a, 2);  
	U = p.encrypt(0);
	 for(int i=0;i<m;i++)
	 {
	    mpz_pow_ui(t_i.get_mpz_t(), a, i);//计算a的i次方
            cout<<"t_i : "<<t_i<<endl;
	        mpz_class temp = p.constMult(t_i,vec[i]);
            //cout<<"temp : "<<pp.decrypt(temp)<<endl;
            U = p.add(temp,U);
            //cout<<"U : "<<pp.decrypt(U)<<endl;
	 }
	return U;
}

mpz_class exec_SVR(tcp::socket &socket,mpz_class E_x,vector<mpz_class> vec_Ex,int m,mpz_class N,gmp_randstate_t rand_state_,Paillier &p)
{
     vector<mpz_class> vec_exi = vec_Ex;
     mpz_class r,U; 
     U = bits2mpz(vec_Ex,m,p);//二进制转为10进制
     mpz_class V = p.sub(U,E_x);
     mpz_urandomm(r.get_mpz_t(),rand_state_,N.get_mpz_t());//随机选择r
     mpz_class W = p.constMult(r,V);

     //send W to server
     Protobuf::BigInt setup_message = convert_to_message(W);
     sendMessageToSocket(socket, setup_message);
    
     //get r from server
       Protobuf::BigInt r_message = readMessageFromSocket<Protobuf::BigInt>(socket);
        mpz_class result = convert_from_message(r_message);
      
     return result;
}

/*
*求乘法逆元
*/
void exgcd(mpz_class a, mpz_class b, mpz_class& d, mpz_class& x, mpz_class& y){
	if (!b){
		d = a;
		x = 1;
		y = 0;
	}
	else
	{
		exgcd(b, a%b, d, y, x);
		y -= x*(a / b);
	}
}
mpz_class inv(mpz_class a, mpz_class p){
	mpz_class d, x, y;
	exgcd(a, p, d, x, y);
        if(d==1)
        {
           return (x + p) % p ;
        }
        return -1;
}

vector<mpz_class> exec_SBD(tcp::socket &socket,mpz_class E_x,mpz_class N,int m,gmp_randstate_t rand_state_,Paillier &p)
{
     vector<mpz_class> vec_Exi;
     mpz_class l = inv(2,N);//2的乘法逆元
     cout<<"l : "<<l<<endl;
     cout<<"m : "<<m<<endl;
     step2: 
     mpz_class E_xi,Z,T = E_x;

     //send m to server
     mpz_class M = m;
     Protobuf::BigInt setup_message = convert_to_message(M);
     sendMessageToSocket(socket, setup_message);
    
    

     for(int i=0;i<m;i++)
     {
	E_xi = exec_Encrypted_LSB(socket,T,i,N,rand_state_,p);
	Z = p.sub(T,E_xi);
	T = p.constMult(l,Z);
        vec_Exi.push_back(E_xi);
     }
     mpz_class ta = exec_SVR(socket,E_x,vec_Exi,m,N,rand_state_,p);
     cout<<"ta : "<<ta<<endl;
     if(ta == 1){
         return vec_Exi;
     }else
     {
         cout<<"SBD failed ! "<<endl;
         //goto step2;
     }
     return vec_Exi ;
}

mpz_class exec_SM(tcp::socket &socket,mpz_class e_a,mpz_class e_b,mpz_class N,Paillier &p,gmp_randstate_t rand_state_)
{
       mpz_class r_a,r_b;
	mpz_urandomm(r_a.get_mpz_t(),rand_state_,N.get_mpz_t());//随机选择r_a
	mpz_urandomm(r_b.get_mpz_t(),rand_state_,N.get_mpz_t());//随机选择r_b
	mpz_class a_ = p.add(e_a,p.encrypt(r_a));
	mpz_class b_ = p.add(e_b,p.encrypt(r_b));
	
        vector<mpz_class> sm(2);
        sm[0]=a_;sm[1]=b_;
        
        //send a_,b_ to server 
        Protobuf::BigIntArray setup_message = convert_to_message(sm);
        sendMessageToSocket(socket, setup_message);


        //get e_h from server
        Protobuf::BigInt e_h_message = readMessageFromSocket<Protobuf::BigInt>(socket);
        mpz_class e_h = convert_from_message(e_h_message);
     
       
        mpz_class temp = p.constMult(r_b,e_a);
	mpz_class s = p.sub(e_h,temp);//e_h -r_b*e_a
	temp = p.constMult(r_a,e_b);
	s = p.sub(s,temp);
	mpz_class result = p.sub(s,p.encrypt(r_a*r_b));

        //send result to server
     //   Protobuf::BigInt re_message = convert_to_message(result);
       // sendMessageToSocket(socket, re_message);


	//cout<<"result : "<<pp.decrypt(result)<<endl;
	return result;
       
}

mpz_class exec_SBOR(tcp::socket &socket,mpz_class o1,mpz_class o2,mpz_class N,Paillier &p,gmp_randstate_t rand_state_)
{
         mpz_class min_o1o2 = exec_SM(socket,o1,o2,N,p,rand_state_);
	 mpz_class add_o1o2 = p.add(o1,o2);
	 mpz_class max_o1o2 = p.sub(add_o1o2,min_o1o2);
	  
         //send max_o1o2 to server
         Protobuf::BigInt max_message = convert_to_message(max_o1o2);
         sendMessageToSocket(socket, max_message);


	 //cout<<"max_o1o2 : "<<pp.decrypt(max_o1o2)<<endl;
	return max_o1o2;
}

void exec_FHE_add_helper(tcp::socket &socket,FHEPubKey& publicKey)
{
        
	cout<<"get c1 c2 from server"<<endl;
        Ctxt c1 = read_fhe_ctxt_from_socket(socket,publicKey);
    
        Ctxt c2 = read_fhe_ctxt_from_socket(socket,publicKey);
        
        
        // compute c1+c2
        c1 += c2;
        
        cout<<" send c1_2 to server"<<endl;
        send_fhe_ctxt_to_socket(socket,c1);
}


void exec_GETMINn_Right(tcp::socket &socket,mpz_class o1)
{
       cout<<"getMINn is right testing"<<endl;
       Protobuf::BigInt max_message = convert_to_message(o1);
       sendMessageToSocket(socket, max_message);

}


vector<Ctxt> exec_calcDis(tcp::socket &socket,vector<Ctxt> test_data,mpz_class n1,mpz_class n2,FHEPubKey& publicKey)
{
    vector<Ctxt> vec_train;
    vector<vector<Ctxt>> matrix_train;
    cout<<" get train data from server"<<endl;
    cout<<"n1: "<<n1<<" , n2: "<<n2<<endl;
    for(mpz_class i=0; i<n1; i++)
    {
       for(mpz_class j=0; j<n2; j++)
       {
           vec_train.push_back(read_fhe_ctxt_from_socket(socket, publicKey));
           cout<<"*";
       }
       matrix_train.push_back(vec_train);
       vec_train.clear();
    }
       
    Ctxt c(publicKey);
    vector<Ctxt> vec_dis,vec_sub;
    cout<<"size : "<<matrix_train.size()<<endl;
    // calculate distance between test and train
    for(int i = 0; i < matrix_train.size(); i++)
    {
        vec_train = matrix_train[i];
        for(int j=0;j<vec_train.size();j++) 
        {
             vec_train[j] -= test_data[j]; 
        }
        innerProduct(c,vec_train,vec_train);
        vec_dis.push_back(c);
    }

        
    // result right test
    /*for(int i = 0; i < vec_dis.size(); i++)
    {
        send_fhe_ctxt_to_socket(socket,vec_dis[i]);
    }
    */
    return vec_dis;
    
}
