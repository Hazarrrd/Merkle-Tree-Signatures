# MerkleTreeRepository
The paper concerns the theoretical description and implementation of the digital signature scheme based on the hierarchy of Merkel trees of different heights. At the beginning the need for such schemes is determined and the currently used digital signature algorithms are introduced. In the next part, the algorithms which are part of digital signatures using the Merkel tree hierarchy method are described in detail. The implementation and communication between the application generating signatures and the verification application is shown (ASN.1 notation is used here). Finally, the results of performance tests and comparison with XMSS+ scheme are shown.

Keywords: digital signatures, Merkle tree, post-quantum cryptography, hash functions, implementation, XMSS, ASN.1

---------------------------------------------------------------------------------------------------------------------------

Praca dotyczy opisu teoretycznego i implementacji schematu podpisów cyfrowych opartych o hierarchię drzew Merkla o różnych wysokościach. Na początku określone jest zapotrzebowanie na takie schematy i przedstawione zostają aktualnie wykorzystywane algorytmy podpisów cyfrowych. W dalszej części szczegółowo omówione zostały algorytmy wchodzące w skład podpisów cyfrowych metodą hierarchii drzew Merkla. Omówiona jest implementacja i komunikacja między aplikacją generującą podpisy a weryfikującą (została tu wykorzystana notacja ASN.1). Na koniec ukazane są wyniki testów wydajnościowych i porównania ze schematem XMSS+.

Słowa klucze : podpisy cyfrowe, drzewo Merla, kryptografia post-quantum, funkcje haszujące, implementacja, XMSS, ASN.1


- Folder MerkleSignatureScheme - zawiera kod źródłowy aplikacji podpisującej oraz aplikacji weryfikującej podpisy cyfrowe

    	- folder algorithm - posiada kody źródłowe aplikacji i klas niezbędnych do działania algorytmu

    	- folder applications - zawiera aplikację podpisującą oraz aplikację weryfikującą

            - plik SignerApplication.java - aplikacja generująca podpisy cyfrowe (posiada metodę main)
            - plik VerifyApplicaton.java - aplikacja weryfikująca podpisy cyfrowe (posiada metodę main)

        - folder keys - zawiera pakiet klas reprezentujących klucze oraz odpowiedzialnych za ich generację
        - folder merkleTree - zawiera pakiet klas implementujących drzewo Merkla i związane z nim operacje i struktury
        - folder signing - zawiera pakiet klas odpowiedzialnych za generowanie podpisów cyfrowych
        - folder tools - zawiera pakiet klas pomocniczych oraz definicje funkcji pseudolosowej, generatora, funkcji haszującej oraz obiektów ASN.1
        - folder verification - zawiera pakiet klas odpowiedzialnych za weryfikację podpisów cyfrowych

        - folder tests - tu się znajduje klasa przeprowadzająca test wydajnościowe, klasa pomocnicza do rysowania wykresów i klasy testów jednostkowych

            - plik Chart.java - klasa odpowiedzialna za rysowanie wykresów
            - plik PerformanceTest.java - klasa przeprowadzająca testy wydajnościowe (posiada metodę main)
            - folder unitTests - przetrzymuje klasy zawierające testy jednostkowe klas z folderu algorithm


W celu uruchomienia aplikacji generującej oraz podpisującej, należy zbudować projekt oraz wywołać kolejno klasy: SignerApplication.java oraz VerifyApplicaton.java.
