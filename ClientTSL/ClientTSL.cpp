#include <iostream>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <curl/curl.h>
#include <json/json.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <ctime>
#include <fstream>

#define PORT 4888 // port, na którym programy będą się komunikować

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcurl_imp.lib")
#pragma comment(lib, "jsoncpp.lib")

#pragma warning(disable:4996)

using namespace std;

const int bufferSize = 1024;

// źródło https://stackoverflow.com/questions/9786150/save-curl-content-result-into-a-string-in-c
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{   //funkcja wywołania zwrotnego jest wywoływana przez libcurl, gdy tylko otrzymane zostaną dane, które należy zapisać
    //contents wskazuje na dostarczone dane, a rozmiar tych danych to size pomnożone przez nmemb
    //argument userp jest ustawiany przez CURLOPT_WRITEDATA (w naszym przypadku test)
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

void appShutdown(int errLine, SOCKET server_socket, SSL_CTX* ctx, SSL* ssl) {
    if (ssl != 0) {
        SSL_shutdown(ssl); // kończy bezpieczne połączenie SSL
        SSL_free(ssl); // zwalnia pamięć zaalokowaną dla zmiennej ssl, która przechowuje informacje o połączeniu SSL
    }
    if (server_socket != 0) closesocket(server_socket); // zamyka gniazdo serwera

    if (&ctx != 0) SSL_CTX_free(ctx); // zwalnia pamięć zaalokowaną dla kontekstu SSL
    WSACleanup(); // kończy pracę z Winsock 

    throw errLine;
}

int main(void)
{
    try {
        int socketClient = 0;
        SSL* ssl = 0;
        SSL_CTX* ctx = 0;
        system("title TSL Client"); // nadanie nazwy konsoli

        CURL* curl;
        CURLcode res;

        std::string test = "";

        curl = curl_easy_init(); // inicjalizacja sesji
        string jsonVal;
        string temperatura, cisnienie;
        if (curl) {
            size_t read_callback(char* buffer, size_t size, size_t nitems, void* userdata);
            curl_easy_setopt(curl, CURLOPT_URL, "https://danepubliczne.imgw.pl/api/data/synop/station/katowice"); //adres wykorzystywanego api
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); //parametr ustawiony na 1 mówi bibliotece, aby podążała za dowolnym nagłówkiem Location:, który serwer wysyła jako część nagłówka HTTP w odpowiedzi na kod 3xx
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback); //wywołuje funkcję WriteCallback
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &test); //przekazuje referencję do stringa test, gdzie będą zapisane dane

            //wykonanie zapytania
            res = curl_easy_perform(curl);
            //sprawdzanie czy wykonanie zapytania się powiodło
            if (res != CURLE_OK) {
                fprintf(stderr, "Blad curl: %s\n", curl_easy_strerror(res));
                throw __LINE__;
            }      
        }

        WSADATA wsaData; // inicjalizacja struktury WSADATA

        WORD version = MAKEWORD(2, 2); // wybranie wersji biblioteki WSADATA
        int Result = WSAStartup(version, &wsaData); // wywołanie funkcji inicjującej winsock
        if (Result != 0) // kontrola poprawności inicjalizacji
        {
            cout << "Nie udalo sie rozpoczac Winsock! " << Result;
            appShutdown(__LINE__, socketClient, ctx, ssl);
        }

        // Tworzenie kontekstu SSL
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            cout << "W SSL_CTX_new wystąpił blad" << endl;
            WSACleanup(); // kończy pracę z Winsock
            appShutdown(__LINE__, socketClient, ctx, ssl);
        }

        // Ustawianie ścieżki do certyfikatu klienta
        if (SSL_CTX_use_certificate_file(ctx, "ClientDPKK.crt", SSL_FILETYPE_PEM) <= 0) {
            cout << "W SSL_CTX_use_certificate_file wystąpił blad" << endl;
            ERR_print_errors_fp(stderr);
            appShutdown(__LINE__, socketClient, ctx, ssl);
        }

        // Ustawianie ścieżki do klucza prywatnego klienta
        if (SSL_CTX_use_PrivateKey_file(ctx, "ClientDPKK.key", SSL_FILETYPE_PEM) <= 0) {
            cout << "W SSL_CTX_use_PrivateKey_file wystąpił blad" << endl;
            ERR_print_errors_fp(stderr);
            appShutdown(__LINE__, socketClient, ctx, ssl);
        }

        socketClient = socket(AF_INET, SOCK_STREAM, 0); // utworzenie gniazda sieciowego
        if (socketClient == INVALID_SOCKET) {
            printf("Nie udalo sie utworzyc socketu: %d", WSAGetLastError());
            appShutdown(__LINE__, socketClient, ctx, ssl);
        }
        sockaddr_in socketServer; // inicjalizacja struktury z adresem serwera
        socketServer.sin_family = AF_INET; // wybranie rodziny adresów dla servera (IPV4)
        socketServer.sin_port = htons(4888); // wybranie portu na którym działa serwer
        memset(socketServer.sin_zero, '\0', sizeof socketServer.sin_zero); // wypełnienie sin_zero zerami

        if (inet_pton(AF_INET, "127.0.0.1", &socketServer.sin_addr) == NULL) { // konwersja adresu i przekazanie do struktury
            cout << "Wystapil blad przy pobieraniu adresu" << endl; // sprawdzenie poprawności połączenia
            appShutdown(__LINE__, socketClient, ctx, ssl);
        }

        if (connect(socketClient, (struct sockaddr*)&socketServer, sizeof(socketServer)) != 0) { // nawiązanie połączenia z serwerem
            cout << "Nie udalo się utworzyc polaczenia" << endl; // sprawdzenie poprawności połączenia
            appShutdown(__LINE__, socketClient, ctx, ssl);
        }

        // Tworzenie połączenia SSL
        ssl = SSL_new(ctx);
        if (!ssl) {
            cerr << "W SSL_new wystapil blad" << endl;
            appShutdown(__LINE__, socketClient, ctx, ssl);
        }

        SSL_set_fd(ssl, socketClient);
        if (SSL_connect(ssl) <= 0) {
            cerr << "W SSL_connect wystapil blad" << endl;
            SSL_free(ssl); // zwalnia pamięć zaalokowaną dla zmiennej ssl, która przechowuje informacje o połączeniu SSL
            closesocket(socketClient); // zamyka gniazdo serwera
            SSL_CTX_free(ctx); // zwalnia pamięć zaalokowaną dla kontekstu SSL
            WSACleanup(); // kończy pracę z Winsock
            throw __LINE__;
        }

        char buffer[bufferSize];

        if (curl) {
            int remainingAmount = 0;
            remainingAmount = test.length();

            if ((SSL_write(ssl, test.c_str(), remainingAmount)) <= 0) {
                SSL_shutdown(ssl); // kończy bezpieczne połączenie SSL
                SSL_free(ssl); // zwalnia pamięć zaalokowaną dla zmiennej ssl, która przechowuje informacje o połączeniu SSL
                closesocket(socketClient); // zamyka gniazdo serwera
                SSL_CTX_free(ctx); // zwalnia pamięć zaalokowaną dla kontekstu SSL
                WSACleanup(); // kończy pracę z Winsock
                return __LINE__;
            }

            //koniec sesji, zamknięcie połączeń
            curl_easy_cleanup(curl);
        }

        cout << "Wyslano informacje do serwera." << endl;

        SSL_shutdown(ssl); // kończy bezpieczne połączenie SSL
        SSL_free(ssl); // zwalnia pamięć zaalokowaną dla zmiennej ssl, która przechowuje informacje o połączeniu SSL
        closesocket(socketClient); // zamyka gniazdo serwera
        SSL_CTX_free(ctx); // zwalnia pamięć zaalokowaną dla kontekstu SSL
        WSACleanup(); // kończy pracę z Winsock
        return 0;
    }
    catch (int ex) {
        std::cout << "Program zakonczyl wykonywanie z bledem w linii: " << ex;
    }
}