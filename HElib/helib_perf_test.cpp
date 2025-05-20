#include <helib/helib.h>
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
    std::cout << "HElib BGV Performance Test\n------------------\n";
    
    // Исправленные параметры BGV схемы
    unsigned long p = 65537;   // Не слишком большое, но > 3 для корректных результатов
    unsigned long m = 8192;    // Даст много слотов и хорошую безопасность
    unsigned long r = 1;       // Подъем
    unsigned long c = 2;       // Столбцы генерирующей матрицы
    
    // Инициализация контекста
    double contextTime = measureTime([&]() {
        helib::Context context = helib::ContextBuilder<helib::BGV>()
            .m(m).p(p).r(r).c(c).build();
    });
    std::cout << "Context initialization: " << contextTime << " s\n";
    
    // Создание контекста для тестирования
    helib::Context context = helib::ContextBuilder<helib::BGV>()
        .m(m).p(p).r(r).c(c).build();
    
    // Генерация ключей
    double keyGenTime = measureTime([&]() {
        helib::SecKey secretKey(context);
        secretKey.GenSecKey();
        helib::addSome1DMatrices(secretKey);
    });
    std::cout << "Key generation: " << keyGenTime << " s\n";
    
    // Создание ключей
    helib::SecKey secretKey(context);
    secretKey.GenSecKey();
    helib::addSome1DMatrices(secretKey);
    const helib::PubKey& publicKey = secretKey;
    
    // Получаем объект для шифрования
    const helib::EncryptedArray& ea = context.getEA();
    long nslots = ea.size();
    std::cout << "Number of slots: " << nslots << std::endl;
    
    // Подготовка данных
    std::vector<long> plaintext1(nslots, 1);
    std::vector<long> plaintext2(nslots, 2);
    
    // Шифрование
    helib::Ctxt ctxt1(publicKey), ctxt2(publicKey);
    double encTime = measureTime([&]() {
        ea.encrypt(ctxt1, publicKey, plaintext1);
        ea.encrypt(ctxt2, publicKey, plaintext2);
    });
    std::cout << "Encryption (2 vectors): " << encTime << " s\n";
    
    // Гомоморфное сложение
    double addTime = measureTime([&]() {
        ctxt1 += ctxt2;
    });
    std::cout << "Homomorphic addition: " << addTime << " s\n";
    
    // Создаем новые шифртексты для умножения
    helib::Ctxt ctxt3(publicKey), ctxt4(publicKey);
    ea.encrypt(ctxt3, publicKey, plaintext1);
    ea.encrypt(ctxt4, publicKey, plaintext2);
    
    // Гомоморфное умножение
    double multTime = measureTime([&]() {
        ctxt3 *= ctxt4;
    });
    std::cout << "Homomorphic multiplication: " << multTime << " s\n";
    
    // Расшифрование
    std::vector<long> result(nslots);
    double decTime = measureTime([&]() {
        ea.decrypt(ctxt1, secretKey, result);
    });
    std::cout << "Decryption: " << decTime << " s\n";
    
    // Проверка результата
    std::cout << "Decrypted result (first 5 values): ";
    for (int i = 0; i < 5 && i < result.size(); i++) {
        std::cout << result[i] << " ";
    }
    std::cout << std::endl;
    
    return 0;
}
