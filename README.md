# MerkleTreeRepository
The paper concerns the theoretical description and implementation of the digital signature scheme based on the hierarchy of Merkel trees of different heights. At the beginning the need for such schemes is determined and the currently used digital signature algorithms are introduced. In the next part, the algorithms which are part of digital signatures using the Merkel tree hierarchy method are described in detail. The implementation and communication between the application generating signatures and the verification application is shown (ASN.1 notation is used here). Finally, the results of performance tests and comparison with XMSS+ scheme are shown.

Keywords: digital signatures, Merkle tree, post-quantum cryptography, hash functions, implementation, XMSS, ASN.1

---------------------------------------------------------------------------------------------------------------------------

Praca dotyczy opisu teoretycznego i implementacji schematu podpisów cyfrowych opartych o hierarchię drzew Merkla o różnych wysokościach. Na początku określone jest zapotrzebowanie na takie schematy i przedstawione zostają aktualnie wykorzystywane algorytmy podpisów cyfrowych. W dalszej części szczegółowo omówione zostały algorytmy wchodzące w skład podpisów cyfrowych metodą hierarchii drzew Merkla. Omówiona jest implementacja i komunikacja między aplikacją generującą podpisy a weryfikującą (została tu wykorzystana notacja ASN.1). Na koniec ukazane są wyniki testów wydajnościowych i porównania ze schematem XMSS+.

Słowa klucze : podpisy cyfrowe, drzewo Merla, kryptografia post-quantum, funkcje haszujące, implementacja, XMSS, ASN.1

\begin{itemize}
	\item Plik \texttt{W11\_236441\_2020\_praca\_inżynierska.pdf} - zawierający pracę dyplomową
    \item Folder \texttt{MerkleSignatureScheme} - zawiera kod źródłowy aplikacji podpisującej oraz aplikacji weryfikującej podpisy cyfrowe
    \begin{itemize}
    	\item folder \texttt{algorithm} - posiada kody źródłowe aplikacji i klas niezbędnych do działania algorytmu
    	\begin{itemize}
    	\item folder \texttt{applications} - zawiera aplikację podpisującą oraz aplikację weryfikującą
    	\begin{itemize}
    	\item plik \texttt{SignerApplication.java} - aplikacja generująca podpisy cyfrowe (posiada metodę \texttt{main})
        \item plik \texttt{VerifyApplicaton.java} - aplikacja weryfikująca podpisy cyfrowe (posiada metodę \texttt{main})
        \end{itemize}
        \item folder \texttt{keys} - zawiera pakiet klas reprezentujących klucze oraz odpowiedzialnych za ich generację
        \item folder \texttt{merkleTree} - zawiera pakiet klas implementujących drzewo Merkla i związane z nim operacje i struktury
        \item folder \texttt{signing} - zawiera pakiet klas odpowiedzialnych za generowanie podpisów cyfrowych
        \item folder \texttt{tools} - zawiera pakiet klas pomocniczych oraz definicje funkcji pseudolosowej, generatora, funkcji haszującej oraz obiektów ASN.1
        \item folder \texttt{verification} - zawiera pakiet klas odpowiedzialnych za weryfikację podpisów cyfrowych
    \end{itemize}
        \item folder \texttt{tests} - tu się znajduje klasa przeprowadzająca test wydajnościowe, klasa pomocnicza do rysowania wykresów i klasy testów jednostkowych
        \begin{itemize}
    	\item plik \texttt{Chart.java} - klasa odpowiedzialna za rysowanie wykresów
        \item plik \texttt{PerformanceTest.java} - klasa przeprowadzająca testy wydajnościowe (posiada metodę \texttt{main})
        \item folder \texttt{unitTests} - przetrzymuje klasy zawierające testy jednostkowe klas z folderu \texttt{algorithm}
    \end{itemize}
    \end{itemize}
\end{itemize}

W celu uruchomienia aplikacji generującej oraz podpisującej, należy zbudować projekt oraz wywołać kolejno klasy: \texttt{SignerApplication.java} oraz \texttt{VerifyApplicaton.java}.
