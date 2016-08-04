package main

// inspired by: https://golang.org/src/crypto/tls/generate_cert.go
// BSD license

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"github.com/boltdb/bolt"
	"log"
	"math/big"
	"net"
	"os"
	"os/user"
	"sort"
	"strconv"
	"time"
)

func assertSuccess(err error) {
	if err != nil {
		panic(err)
	}
}

type RsaKeyLength int64
type rsaKeyLengthFlag struct{ RsaKeyLength }

func (r *rsaKeyLengthFlag) Set(s string) error {
	i, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	j := RsaKeyLength(i)
	r.RsaKeyLength = j
	return nil
}

func (r *rsaKeyLengthFlag) String() string {
	return strconv.FormatInt(int64(r.RsaKeyLength), 10)
}

func RsaKeyLengthFlag(name string, value RsaKeyLength, usage string) *RsaKeyLength {
	e := log.New(os.Stderr, "", 0)
	e.Println(value)
	r := rsaKeyLengthFlag{value}
	flag.CommandLine.Var(&r, name, usage)
	return &r.RsaKeyLength
}

var (
	err             error
	cadb            string
	caKeyLength     = RsaKeyLengthFlag("ca_key_length", 4096, "Key size (RSA) for CA signing certificate.")
	caValidFor      = flag.Duration("ca_valid_for", 10*365*24*time.Hour, "Duration the CA certificate is valid for")
	command         = flag.String("command", "help", "CA command")
	commonName      = flag.String("cert_common_name", "", "Certificate Common Name (e.g. 'www.mycompany.net', 'My Company CA')")
	hostKeyLength   = RsaKeyLengthFlag("host_key_length", 2048, "Key size (RSA) for host certificates.")
	hostValidFor    = flag.Duration("host_valid_for", 1*365*24*time.Hour, "Duration the host certificate are valid for")
	organization    = flag.String("cert_organization", "", "Certificate Organization (e.g. 'My Company')")
	serial          = flag.Uint64("id", 0, "ID (Certificate Serial Number)")
	subjectAltNames = flag.String("subject_alt_names", "", "Optional.  Comma-separated list of hostnames or IP addresses.")
	validFrom       = flag.String("start-date", "", "Certificate start date.  Fomatted as: '2016/06/15 21:42:51'")
	isCA            = false
	validCommands   = map[string]string{
		"createCertificate":    "Create a new host certificate.",
		"exportCertificatePEM": "Export a certificate in PEM format.",
		"exportCRL":            "Export Certificate Revocation List.",
		"exportKeyPEM":         "Export a certificate's key in PEM format.",
		"help":                 "Display general help/usage.",
		"init":                 "Initialize Certificate Authority.",
		"list":                 "List all certificates.",
		"revoke":               "Revoke a certificate.",
	}
)

// printCommands prints out valid strings accepted by -command= argument.
func printCommands() {
	e := log.New(os.Stderr, "", 0)

	// To store the keys in slice in sorted order
	var keys []string
	for k := range validCommands {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	e.Println("\n\nValid Commands:")
	for _, k := range keys {
		e.Printf("  %-21s: %s", k, validCommands[k])
	}
}

// init will abort the program if cadb file exists wih incorrect permissions.
// It also creates the database file, if one doesn't already exist.
// NOTICE: This is the golang init function
func init() {
	usr, err := user.Current()
	assertSuccess(err)

	flag.StringVar(&cadb, "cadb", usr.HomeDir+"/.cadb", "CA database file")

	if _, err := os.Stat(cadb); os.IsNotExist(err) {
		f, err := os.OpenFile(cadb, os.O_CREATE, 0600)
		assertSuccess(err)
		f.Close()
	}

	fileInfo, err := os.Stat(cadb)
	assertSuccess(err)
	if fileInfo.Mode() != 0600 {
		log.Fatalf("The cadb file (%s) has bad permissions (should be 0600), aborting.", cadb)
	}
}

func generateSerialNumber(db *bolt.DB, commonName string) (n *big.Int, err error) {
	var serialNumber *big.Int = nil
	err = db.Update(func(tx *bolt.Tx) error {

		b := tx.Bucket([]byte("SerialNumbers"))

		for serialNumber == nil {
			serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
			assertSuccess(err)

			// what are the odds a serial number already exists?
			if b.Get([]byte(serialNumber.String())) != nil {
				serialNumber = nil
			}
		}

		err = b.Put([]byte(serialNumber.String()), []byte(commonName))

		return nil
	})
	return serialNumber, err
}

func performInit(db *bolt.DB) {
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("CaConfig"))
		if b == nil {
			b, err = tx.CreateBucketIfNotExists([]byte("CaConfig"))
			assertSuccess(err)

			err = b.Put([]byte("schema_version"), []byte("1"))
			assertSuccess(err)

			err = b.Put([]byte("ca_cert_keylen"), []byte(strconv.FormatInt(int64(*caKeyLength), 10)))
			assertSuccess(err)

			err = b.Put([]byte("host_default_keylen"), []byte(strconv.FormatInt(int64(*hostKeyLength), 10)))
			assertSuccess(err)

			err = b.Put([]byte("ca_commonname"), []byte(*commonName))
			assertSuccess(err)

			err = b.Put([]byte("ca_organization"), []byte(*organization))
			assertSuccess(err)

			err = b.Put([]byte("ca_serial_number"), []byte("1"))
			assertSuccess(err)

			err = b.Put([]byte("ca_key"), []byte(""))
			assertSuccess(err)

			err = b.Put([]byte("ca_certificate"), []byte(""))
			assertSuccess(err)
		}

		b, err = tx.CreateBucketIfNotExists([]byte("SerialNumbers"))
		b, err = tx.CreateBucketIfNotExists([]byte("RevokedCertificates"))
		b, err = tx.CreateBucketIfNotExists([]byte("HostCertificates"))
		b, err = tx.CreateBucketIfNotExists([]byte("HostKeys"))

		return nil
	})
	assertSuccess(err)

	var priv *rsa.PrivateKey
	priv, err = rsa.GenerateKey(rand.Reader, int(*caKeyLength))
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}

	var notBefore time.Time
	if len(*validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("2016/06/15 21:42:51", *validFrom)
		assertSuccess(err)
	}

	notAfter := notBefore.Add(*caValidFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	assertSuccess(err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   *commonName,
			Organization: []string{*organization},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(*commonName); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, *commonName)
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	assertSuccess(err)

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("CaConfig"))

		err = b.Put([]byte("ca_certificate"), derBytes)
		assertSuccess(err)

		return nil
	})
	assertSuccess(err)

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("CaConfig"))

		err = b.Put([]byte("ca_key"), x509.MarshalPKCS1PrivateKey(priv))
		assertSuccess(err)

		return nil
	})
	assertSuccess(err)
}

func performCreate(db *bolt.DB) {
	log.Fatalf("Not implemented...")
}

func performList(db *bolt.DB) {
	sn, err := generateSerialNumber(db, *commonName)
	assertSuccess(err)
	log.Fatalf(sn.String())
}

func performExportCertificatePEM(db *bolt.DB) {
	if err := db.View(func(tx *bolt.Tx) error {

		keyOut, err := os.OpenFile("cert.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Print("failed to open cert.pem for writing:", err)
			return nil
		}

		value := tx.Bucket([]byte("CaConfig")).Get([]byte("ca_certificate"))
		log.Print("The value of 'ca_certificate' is: %s\n", pem.Encode(keyOut, &pem.Block{Type: "CERTIFICATE", Bytes: value}))
		return nil
	}); err != nil {
		log.Fatal(err)
	}

	return
}

func performExportKeyPEM(db *bolt.DB) {
	if err := db.View(func(tx *bolt.Tx) error {

		keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Print("failed to open key.pem for writing:", err)
			return nil
		}

		value := tx.Bucket([]byte("CaConfig")).Get([]byte("ca_key"))
		log.Print("The value of 'ca_key' is: %s\n", pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: value}))
		return nil
	}); err != nil {
		log.Fatal(err)
	}

	return
}

func performExportCRL(db *bolt.DB) {
	log.Fatalf("Not implemented...")
}

func performRevoke(db *bolt.DB) {
	log.Fatalf("Not implemented...")
}

func main() {
	flag.Parse()

	db, err := bolt.Open(cadb, 0600, nil)
	assertSuccess(err)
	defer db.Close()

	if len(*command) == 0 {
		flag.PrintDefaults()
		printCommands()
		log.Fatalf("Missing required --command parameter")
	}

	switch *command {
	case "list":
		performList(db)
	case "createCertificate":
		performCreate(db)
	case "exportCertificate":
		performExportCertificatePEM(db)
	case "exportKey":
		performExportKeyPEM(db)
	case "exportCRL":
		performExportCRL(db)
	case "revoke":
		performRevoke(db)
	case "init":
		performInit(db)
	default:
		flag.PrintDefaults()
		printCommands()
		log.Fatalf("")
	}
}
