package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
)

//RSA

type RsaKeys struct {
	n *big.Int
	e *big.Int
	d *big.Int
}

type RsaSign struct {
	N         *big.Int `json:"N"`
	E         *big.Int `json:"E"`
	FilePath  string   `json:"filePath"`
	Signature *big.Int `json:"signature"`
}

// Генератор n-бітного простого числа
func generatePrime(bits int) (*big.Int, error) {
	prime, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return prime, nil
}

// Функція генерації взаємнопростого числа
func genCoPrime(phi *big.Int) (*big.Int, error) {
	e := new(big.Int).SetInt64(65537) // популярна відкрита експонента
	gcd := new(big.Int).GCD(nil, nil, e, phi)
	if gcd.Cmp(big.NewInt(1)) == 0 {
		return e, nil
	}
	maxExponent := new(big.Int).Exp(big.NewInt(2), big.NewInt(16), nil)

	// Генерація випадкового e
	e, err := rand.Int(rand.Reader, maxExponent)
	if err != nil {
		return nil, err
	}

	// Перевірка, що 1 < e < phi(n) та gcd(e, phi(n)) = 1
	for e.Cmp(big.NewInt(1)) <= 0 || e.Cmp(phi) >= 0 || new(big.Int).GCD(nil, nil, e, phi).Cmp(big.NewInt(1)) != 0 {
		e, err = rand.Int(rand.Reader, maxExponent)
		if err != nil {
			return nil, err
		}
	}

	return e, nil
}

// Функція генерації ключів
func GenerateKey() *RsaKeys {
	//Генерація p,q,n
	p, _ := generatePrime(1024)
	q, _ := generatePrime(1024)
	n := new(big.Int).Mul(p, q)
	//Генерація функції Ейлера
	pMinusOne := new(big.Int).Sub(p, big.NewInt(1))
	qMinusOne := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(pMinusOne, qMinusOne)
	//Знаходження d, e
	e, _ := genCoPrime(phi)
	d := new(big.Int).ModInverse(e, phi)
	keys := RsaKeys{n, e, d}
	return &keys
}

// Функція для обчислення SHA-256 хешу файлу
func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()

	_, err = io.Copy(hasher, file)
	if err != nil {
		return "", err
	}

	// Переміщує вказівник файлу на початок
	_, err = file.Seek(0, 0)
	if err != nil {
		return "", err
	}

	hashInBytes := hasher.Sum(nil)
	hash := hex.EncodeToString(hashInBytes)

	return hash, nil
}

// Функція для серіалізації даних підпису
func JsonMARSHAL(r *RsaSign) string {
	jsonData, err := json.Marshal(r)
	if err != nil {
		fmt.Println("Помилка маршалінгу:", err)
	}
	return string(jsonData)
}

// Функція для десеріалізації даних підпису
func JsonUNMARSHAL(jsonData string) *RsaSign {
	var newRsaSign RsaSign
	err := json.Unmarshal([]byte(jsonData), &newRsaSign)
	if err != nil {
		fmt.Println("Помилка анмаршалінгу:", err)
	}
	return &newRsaSign
}

func (r *RsaKeys) Sign(filePath string) string {
	hash, _ := calculateFileHash(filePath)
	hashBytes := []byte(hash)
	hashInt := new(big.Int).SetBytes(hashBytes)
	S := new(big.Int).Exp(hashInt, r.d, r.n)
	Signature := RsaSign{r.n, r.e, filePath, S}
	return JsonMARSHAL(&Signature)

}

func Verify(sign string) bool {
	SignRSA := JsonUNMARSHAL(sign)
	hash, _ := calculateFileHash(SignRSA.FilePath)
	hashBytes := []byte(hash)
	hashInt := new(big.Int).SetBytes(hashBytes)
	M := new(big.Int).Exp(SignRSA.Signature, SignRSA.E, SignRSA.N)
	return new(big.Int).Mod(hashInt, SignRSA.N).Cmp(new(big.Int).Mod(M, SignRSA.N)) == 0
}

func main() {
	// 1 тест
	filepath := "/home/bonichichni/Documents/Digital_Signature/testfile.txt"
	keysFirstTest := GenerateKey()
	signFirstTest := keysFirstTest.Sign(filepath)
	fmt.Println(Verify(signFirstTest))
	// 2 тест
	fmt.Println()
	keysSecondTest := GenerateKey()
	signSecondTest := keysSecondTest.Sign(filepath)
	file, err := os.OpenFile("/home/bonichichni/Documents/Digital_Signature/testfile.txt", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("Помилка при відкритті файлу:", err)
		return
	}
	defer file.Close()
	newElement := "додаткові символи в файлі"

	// Запис нового елемента у файл
	_, err = file.WriteString(newElement + "\n")
	if err != nil {
		fmt.Println("Помилка при записі у файл:", err)
		return
	}
	fmt.Println(Verify(signSecondTest))
}
