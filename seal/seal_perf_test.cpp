#include "seal/seal.h"
#include <chrono>
#include <iostream>
#include <vector>

// Функция для замера времени
template<typename Func>
double measureTime(Func f) {
    auto start = std::chrono::high_resolution_clock::now();
    f();
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double>(end - start).count();
}

int main() {
    std::cout << "Microsoft SEAL BFV Performance Test\n------------------\n";
    
    // Настройка параметров
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
    
    // Поиск подходящего простого числа для батчинга
    // Оно должно быть простым и ≡ 1 (mod 2*poly_modulus_degree)
    parms.set_plain_modulus(seal::PlainModulus::Batching(poly_modulus_degree, 20));
    
    // Создание контекста
    double contextTime = measureTime([&]() {
        seal::SEALContext context(parms);
    });
    std::cout << "Context creation: " << contextTime << " s\n";
    
    seal::SEALContext context(parms);
    
    // Вывод выбранного модуля
    std::cout << "Using plaintext modulus: " << parms.plain_modulus().value() << std::endl;
    
    // Генерация ключей
    double keyGenTime = measureTime([&]() {
        seal::KeyGenerator keygen(context);
        auto secret_key = keygen.secret_key();
        seal::PublicKey public_key;
        keygen.create_public_key(public_key);
        seal::RelinKeys relin_keys;
        keygen.create_relin_keys(relin_keys);
    });
    std::cout << "Key generation: " << keyGenTime << " s\n";
    
    // Создание ключей для тестирования
    seal::KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    // Инициализация объектов для операций
    seal::Encryptor encryptor(context, public_key);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, secret_key);
    seal::BatchEncoder encoder(context);
    
    // Подготовка данных
    size_t slot_count = encoder.slot_count();
    std::cout << "Number of slots: " << slot_count << std::endl;
    
    std::vector<uint64_t> pod_vector1(slot_count, 1);
    std::vector<uint64_t> pod_vector2(slot_count, 2);
    
    seal::Plaintext plain1, plain2;
    encoder.encode(pod_vector1, plain1);
    encoder.encode(pod_vector2, plain2);
    
    // Шифрование
    seal::Ciphertext cipher1, cipher2;
    double encTime = measureTime([&]() {
        encryptor.encrypt(plain1, cipher1);
        encryptor.encrypt(plain2, cipher2);
    });
    std::cout << "Encryption (2 vectors): " << encTime << " s\n";
    
    // Гомоморфное сложение
    seal::Ciphertext cipher_add;
    double addTime = measureTime([&]() {
        evaluator.add(cipher1, cipher2, cipher_add);
    });
    std::cout << "Homomorphic addition: " << addTime << " s\n";
    
    // Гомоморфное умножение
    seal::Ciphertext cipher_mult;
    double multTime = measureTime([&]() {
        evaluator.multiply(cipher1, cipher2, cipher_mult);
        evaluator.relinearize_inplace(cipher_mult, relin_keys);
    });
    std::cout << "Homomorphic multiplication: " << multTime << " s\n";
    
    // Расшифрование
    seal::Plaintext decrypted_result;
    double decTime = measureTime([&]() {
        decryptor.decrypt(cipher_add, decrypted_result);
    });
    std::cout << "Decryption: " << decTime << " s\n";
    
    // Проверка результата
    std::vector<uint64_t> result;
    encoder.decode(decrypted_result, result);
    std::cout << "Decrypted result (first 5 values): ";
    for (int i = 0; i < 5 && i < result.size(); i++) {
        std::cout << result[i] << " ";
    }
    std::cout << std::endl;
    
    return 0;
}
