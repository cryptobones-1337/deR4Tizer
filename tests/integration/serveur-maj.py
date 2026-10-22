"""Lot 3c : serveur local de la mise à jour (runner jetable seulement).

Sert le même dossier en HTTPS (arborescence des versions GitHub : .../releases/latest/download/manifeste.json,
.../releases/download/v<version>/deR4Tizer.msi) et en HTTP (liste de révocation de la racine de test).
Chaque requête est écrite dans le journal : « port méthode chemin code », une ligne par requête, pour que le
test exige, scénario par scénario, chaque requête attendue.

Usage : python serveur-maj.py <racine> <port_https> <port_http> <certificat> <cle> <journal>
"""
import http.server
import ssl
import sys
import threading


def gestionnaire(racine, port, journal, verrou):
    class Gestionnaire(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=racine, **k)

        def log_request(self, code="-", size="-"):
            with verrou, open(journal, "a", encoding="utf-8") as f:
                f.write(f"{port} {self.command} {self.path} {code}\n")

        def log_message(self, *a):
            pass

    return Gestionnaire


def main():
    racine, port_https, port_http, certificat, cle, journal = sys.argv[1:7]
    verrou = threading.Lock()
    serveurs = []
    for port, tls in ((int(port_https), True), (int(port_http), False)):
        s = http.server.ThreadingHTTPServer(("127.0.0.1", port), gestionnaire(racine, port, journal, verrou))
        if tls:
            contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            contexte.load_cert_chain(certificat, cle)
            s.socket = contexte.wrap_socket(s.socket, server_side=True)
        serveurs.append(s)
    for s in serveurs[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    serveurs[0].serve_forever()


if __name__ == "__main__":
    main()
