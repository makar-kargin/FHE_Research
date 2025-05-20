package main

import (
	"fmt"
	"time"

	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// Функция измерения времени выполнения, возвращающая время в секундах
func measureTime(f func()) float64 {
	start := time.Now()
	f()
	return time.Since(start).Seconds()
}

func main() {
	fmt.Println("Lattigo BFV Performance Test\n------------------")

	// Установка параметров с корректной обработкой ошибок
	var params bfv.Parameters
	var err error
	setupTime := measureTime(func() {
		params, err = bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
			LogN: 13, // N = 8192
			LogQ: []int{55, 55},
			LogP: []int{55},
			T:    65537,
		})
		if err != nil {
			panic(fmt.Sprintf("error setting parameters: %v", err))
		}
	})
	fmt.Printf("Parameter setup: %.6f s\n", setupTime)

	// Генерация ключей
	var kgen rlwe.KeyGenerator
	var sk *rlwe.SecretKey
	var pk *rlwe.PublicKey
	var rlk *rlwe.RelinearizationKey

	keyGenTime := measureTime(func() {
		kgen = rlwe.NewKeyGenerator(params.Parameters)
		sk = kgen.GenSecretKey()
		pk = kgen.GenPublicKey(sk)
		rlk = kgen.GenRelinearizationKey(sk, 1)
	})
	fmt.Printf("Key generation: %.6f s\n", keyGenTime)

	// Создание объектов для операций
	encryptor := rlwe.NewEncryptor(params.Parameters, pk)
	decryptor := rlwe.NewDecryptor(params.Parameters, sk)
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})
	encoder := bfv.NewEncoder(params)

	// Подготовка данных
	plaintext1 := make([]uint64, params.N())
	plaintext2 := make([]uint64, params.N())
	for i := range plaintext1 {
		plaintext1[i] = 1
		plaintext2[i] = 2
	}

	// Кодирование
	polyPlain1 := bfv.NewPlaintext(params, 0)
	polyPlain2 := bfv.NewPlaintext(params, 0)

	encodeTime := measureTime(func() {
		encoder.Encode(plaintext1, polyPlain1)
		encoder.Encode(plaintext2, polyPlain2)
	})
	fmt.Printf("Encoding (2 vectors): %.6f s\n", encodeTime)

	// Шифрование
	cipher1 := rlwe.NewCiphertext(params.Parameters, 1, 0)
	cipher2 := rlwe.NewCiphertext(params.Parameters, 1, 0)

	encryptTime := measureTime(func() {
		encryptor.Encrypt(polyPlain1, cipher1)
		encryptor.Encrypt(polyPlain2, cipher2)
	})
	fmt.Printf("Encryption (2 vectors): %.6f s\n", encryptTime)

	// Гомоморфное сложение
	cipherAdd := rlwe.NewCiphertext(params.Parameters, 1, 0)

	addTime := measureTime(func() {
		evaluator.Add(cipher1, cipher2, cipherAdd)
	})
	fmt.Printf("Homomorphic addition: %.6f s\n", addTime)

	// Гомоморфное умножение
	cipherMult := rlwe.NewCiphertext(params.Parameters, 2, 0)

	multTime := measureTime(func() {
		evaluator.Mul(cipher1, cipher2, cipherMult)
		cipherRelinMult := rlwe.NewCiphertext(params.Parameters, 1, 0)
		evaluator.Relinearize(cipherMult, cipherRelinMult)
	})
	fmt.Printf("Homomorphic multiplication: %.6f s\n", multTime)

	// Расшифрование
	decryptedPlain := bfv.NewPlaintext(params, 0)

	decryptTime := measureTime(func() {
		decryptor.Decrypt(cipherAdd, decryptedPlain)
	})
	fmt.Printf("Decryption: %.6f s\n", decryptTime)

	// Декодирование и проверка результата
	result := make([]uint64, params.N())
	encoder.Decode(decryptedPlain, result)
	fmt.Printf("Decoded result (first 5 values): %v\n", result[:5])
}
