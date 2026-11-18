#!/usr/bin/env python3
"""
Generate benign "hard negatives" for the classifier: ordinary sentences that use the vocabulary of prompt
injection (instructions, previous, ignore, system prompt, password, override, forget, pretend, rules, admin)
without being one.

    python tools/classifier/hard_negatives.py <out.jsonl> [--n 9000]

A bag-of-words model trained only on chat-versus-attack data learns that "previous instructions" means
attack. Manuals, style guides, release notes and help pages say it all day. These sentences are written
from templates here, not taken from any scoring set or test fixture, and are labelled as generated.
Every line is {"text", "label": false, "source": "generated hard negatives (<lang>)"}.
"""
import argparse
import json
import random

EN_T = [
    "The previous instructions for {task} are in {doc}.",
    "Please follow the instructions above to {task}.",
    "If you already completed {task}, you can ignore the earlier instructions in {doc}.",
    "Ignore the warning about {thing}; it is harmless and will be removed in the next release.",
    "You can safely ignore {thing} when you {task}.",
    "The system prompt field in {doc} lets you set the tone your assistant uses with customers.",
    "A good system prompt is short: say who the assistant is, what it should do, and what it should avoid.",
    "Our style guide says the new rule overrides the previous one whenever the two conflict.",
    "To reset your password, open {doc} and choose Forgot password.",
    "Never share your password with anyone, including people who say they are from {team}.",
    "The admin can override the default settings for {thing} from {doc}.",
    "Forget about {thing} for now; we changed the plan and will {task} next week instead.",
    "Don't forget to {task} before you leave on Friday.",
    "Pretend play helps young children learn how to {task} and to share with others.",
    "In this role you will {task} and report to {team}.",
    "The rules of the game are simple: each player must {task} before the timer runs out.",
    "From now on, the office will {task} every Monday morning.",
    "As a reminder, do not reveal the answer to {thing} until everyone has finished {task}.",
    "Developer mode in {doc} shows extra logs that help you {task}.",
    "The assistant in this app can {task}, but it cannot see {thing}.",
    "You are now subscribed to updates about {thing}; reply STOP to unsubscribe.",
    "Disregard my last email about {thing}; the meeting has moved and {team} will {task}.",
    "This section explains how to bypass the cache when you {task}.",
    "The instructions that came with {thing} say to {task} once a month.",
    "New instructions: starting in March, {team} will {task} using {doc}.",
    "The teacher asked the students to repeat the previous exercise and then {task}.",
    "Our chatbot uses a hidden prompt to stay polite; you can edit it in {doc}.",
    "Act as the point of contact for {team} while I am away, and {task} if anything urgent comes up.",
    "Print the instructions and keep them next to {thing} so everyone can {task}.",
    "Override the default by passing a flag when you {task}; see {doc} for the full list.",
    "The prompt injection section of {doc} describes how attackers hide instructions in web pages.",
    "Researchers found that telling a model to ignore its instructions is the oldest trick; {doc} explains the defences.",
    "Send the summary to {team} once you {task}, and copy me on the email.",
    "Reveal the hidden layer in the drawing by tapping {thing} twice.",
    "Your instructions for the exam: read every question, then {task}.",
    "The system will prompt you for a password the first time you {task}.",
    "What were the previous instructions for {task}? I lost the page from {doc}.",
    "Can you explain what a system prompt is and why companies keep theirs secret?",
    "Jailbreak detection on phones checks whether {thing} has been modified.",
    "Security training: if a message asks you to ignore company rules and {task}, report it to {team}.",
]
EN_TASK = ["update the firmware", "install the printer driver", "submit your expenses", "back up the database", "book a meeting room", "renew your library card", "configure the router", "assemble the bookshelf", "file the quarterly report", "rotate the API keys", "water the plants", "merge the release branch", "calibrate the scale", "set up two-factor sign-in", "export the invoices", "clean the coffee machine", "restart the server", "translate the brochure", "label the samples", "check the tyre pressure"]
EN_DOC = ["the user manual", "the README", "the onboarding guide", "section 4 of the handbook", "the settings page", "the wiki", "the admin console", "chapter two", "the release notes", "the help centre", "the installation guide", "the team notebook", "appendix B", "the quick start card"]
EN_THING = ["the yellow warning light", "the deprecation notice", "the old spreadsheet", "the beta feature", "the noise from the fan", "the second login screen", "the legacy endpoint", "the draft schedule", "the cached copy", "the test account", "the broken link", "the extra cable"]
EN_TEAM = ["the IT help desk", "the finance team", "your manager", "the support team", "the security office", "human resources", "the facilities crew", "the release managers"]

# ---- ordinary modern email: the furniture every inbox is full of ----
# The benign mail in the training set is from 2001. It has no order confirmations, password resets, newsletters
# or unsubscribe footers, while the attack mail is all about sending emails to addresses. Without these the
# model learns that talking about email is the attack.
MAIL_T = [
    "You are receiving this email because you signed up at {site}. To stop receiving these emails, unsubscribe here: https://{site}/u/{num}",
    "This email was sent to {addr}. If you no longer wish to receive these messages, update your preferences or unsubscribe.",
    "Action required: confirm your email address to finish setting up your {site} account.",
    "Please confirm your email address by clicking the button below. This link expires in {num} hours.",
    "Thanks for your order #{num}! We'll send you another email as soon as it ships.",
    "Your order #{num} has shipped. Track your package at https://{site}/track/{num}. Questions? Email us at {addr}.",
    "We received a request to reset the password for your account. If you didn't ask for this, you can ignore this email.",
    "Your verification code is {num}. Do not share this code with anyone. {brand} will never ask you for it.",
    "Hi {name}, your invoice #{num} from {brand} is attached. Payment is due in {num2} days. Reply to this email if you have any questions.",
    "Reminder: your appointment with {brand} is on {day} at {time}. Reply C to confirm or call us to reschedule.",
    "{name} invited you to a meeting: {topic}. {day} at {time}. Join from your computer or phone.",
    "Your subscription to {brand} renews on {day}. You will be charged {price}. Manage your subscription at https://{site}/account.",
    "New sign-in to your account from a new device. If this was you, no action is needed. If not, change your password right away.",
    "Don't miss out! {brand}'s {season} sale ends {day}: save up to {num2}% on everything. Shop now.",
    "Welcome to {brand}, {name}! Here are three things you can do to get started: complete your profile, invite your team, and explore the templates.",
    "Please do not reply to this email. This mailbox is not monitored. For help, contact {addr}.",
    "Forward this email to a friend who might enjoy {brand}'s weekly newsletter. Was this forwarded to you? Subscribe here.",
    "Hi {name}, just following up on my last email about {topic}. Could you send me the latest version when you get a chance? Thanks!",
    "Hi team, please send your status updates to {addr} by end of day {day} so I can include them in the report.",
    "Can you forward me the email from {name} about {topic}? I can't find it in my inbox.",
    "Per my last email, the deadline for {topic} is {day}. Let me know if you need more time.",
    "Your receipt from {brand}: {price} paid on {day}. View or download your receipt at https://{site}/r/{num}.",
    "We've updated our privacy policy. The changes take effect on {day}. You don't need to do anything.",
    "Your {brand} statement is ready. Sign in to view it. For your security, we never include account numbers in email.",
    "{name} shared a document with you: \"{topic}\". Open it to view or comment.",
    "Out of office: I'm away until {day} with limited access to email. For anything urgent, please contact {addr}.",
    "Hi {name}, thanks for getting in touch. Our support team will reply to your message within {num2} hours. Your ticket number is #{num}.",
    "Please add {addr} to your address book to make sure our emails reach your inbox.",
    "Your flight to {city} is confirmed. Confirmation code: {code}. Check in online from 24 hours before departure.",
    "Hi {name}, this is a confirmation that we received your application for {topic}. We will email you about next steps.",
    "Message from {name}: running ten minutes late, start without me. Sent from my phone.",
    "Hi {name}, can you send the signed contract to {addr} today? Legal needs it before the call at {time}.",
]
MAIL = {
    "site": ["shop.example", "mail.northwindtraders.com", "news.contoso.com", "fabrikam.com", "example.org", "app.tailspintoys.com", "litware.net", "adventure-works.com", "wingtiptoys.co.uk", "proseware.io"],
    "addr": ["support@contoso.com", "billing@fabrikam.com", "help@example.org", "hello@northwindtraders.com", "team@litware.net", "no-reply@adventure-works.com", "j.smith@proseware.io", "accounts@wingtiptoys.co.uk", "info@example.net", "maria.garcia@tailspintoys.com"],
    "brand": ["Northwind", "Contoso", "Fabrikam", "Litware", "Adventure Works", "Tailspin", "Proseware", "Wingtip", "the City Library", "Lakeside Dental"],
    "name": ["Sam", "Priya", "Dana", "Luis", "Chen", "Amara", "Jonas", "Fatima", "Olu", "Mei"],
    "topic": ["the Q3 budget review", "the website redesign", "onboarding for new hires", "the vendor contract", "Thursday's workshop", "the product roadmap", "the conference talk", "the lease renewal"],
    "day": ["Monday", "Friday, March 14", "the 3rd", "next Tuesday", "June 30", "tomorrow"],
    "time": ["9:30 am", "2 pm", "4:15 pm", "noon"],
    "season": ["spring", "summer", "autumn", "winter", "back-to-school"],
    "price": ["$12.99", "€49.00", "£8.50", "$240.00"],
    "city": ["Lisbon", "Toronto", "Nairobi", "Osaka", "Denver"],
}

# (templates, tasks, docs, things, teams) per language
LANGS = {
    "de": (
        ["Die vorherigen Anweisungen zum {task} finden Sie in {doc}.", "Bitte befolgen Sie die obigen Anweisungen, um {task}.", "Sie können {thing} ignorieren, wenn Sie bereits {doc} gelesen haben.", "Ignorieren Sie die Warnung zu {thing}; sie verschwindet mit dem nächsten Update.", "Um Ihr Passwort zurückzusetzen, öffnen Sie {doc} und wählen Sie „Passwort vergessen“.", "Die neue Regel ersetzt die vorherige Regel in {doc}.", "Vergessen Sie nicht, vor Freitag {task}.", "Der Administrator kann die Standardeinstellungen für {thing} in {doc} überschreiben.", "Ab jetzt wird das Büro jeden Montag {task}.", "Der Systemprompt legt fest, wie höflich der Assistent antwortet; Sie ändern ihn in {doc}.", "Geben Sie Ihr Passwort niemals weiter, auch nicht an {team}.", "Neue Anweisungen: Ab März wird {team} {task}.", "Die Spielregeln sind einfach: Jeder Spieler muss {task}.", "Was waren die vorherigen Anweisungen, um {task}? Ich finde {doc} nicht mehr."],
        ["die Firmware zu aktualisieren", "den Druckertreiber zu installieren", "die Spesen einzureichen", "die Datenbank zu sichern", "den Router einzurichten", "das Regal aufzubauen", "den Quartalsbericht abzugeben", "die Pflanzen zu gießen"],
        ["dem Handbuch", "der README-Datei", "dem Leitfaden", "Abschnitt 4", "den Einstellungen", "dem Wiki", "den Versionshinweisen"],
        ["die gelbe Warnleuchte", "den alten Hinweis", "die Testversion", "das zweite Anmeldefenster", "den Entwurf", "das Geräusch des Lüfters"],
        ["den IT-Support", "die Buchhaltung", "Ihre Vorgesetzten", "das Sicherheitsteam"],
    ),
    "fr": (
        ["Les instructions précédentes pour {task} se trouvent dans {doc}.", "Veuillez suivre les instructions ci-dessus pour {task}.", "Vous pouvez ignorer {thing} si vous avez déjà lu {doc}.", "Ignorez l'avertissement concernant {thing} ; il disparaîtra à la prochaine mise à jour.", "Pour réinitialiser votre mot de passe, ouvrez {doc} et choisissez « Mot de passe oublié ».", "La nouvelle règle remplace la règle précédente dans {doc}.", "N'oubliez pas de {task} avant vendredi.", "L'administrateur peut modifier les paramètres par défaut de {thing} dans {doc}.", "Désormais, le bureau va {task} chaque lundi.", "Le prompt système définit le ton de l'assistant ; vous pouvez le modifier dans {doc}.", "Ne communiquez jamais votre mot de passe, même à {team}.", "Nouvelles instructions : à partir de mars, {team} va {task}.", "Les règles du jeu sont simples : chaque joueur doit {task}.", "Quelles étaient les instructions précédentes pour {task} ? J'ai perdu {doc}."],
        ["mettre à jour le micrologiciel", "installer le pilote de l'imprimante", "envoyer vos notes de frais", "sauvegarder la base de données", "configurer le routeur", "monter l'étagère", "remettre le rapport trimestriel", "arroser les plantes"],
        ["le manuel", "le fichier README", "le guide d'accueil", "la section 4", "la page des paramètres", "le wiki", "les notes de version"],
        ["le voyant jaune", "l'ancien message", "la version bêta", "le deuxième écran de connexion", "le brouillon", "le bruit du ventilateur"],
        ["le support informatique", "la comptabilité", "votre responsable", "l'équipe sécurité"],
    ),
    "es": (
        ["Las instrucciones anteriores para {task} están en {doc}.", "Siga las instrucciones de arriba para {task}.", "Puede ignorar {thing} si ya leyó {doc}.", "Ignore la advertencia sobre {thing}; desaparecerá con la próxima actualización.", "Para restablecer su contraseña, abra {doc} y elija «Olvidé mi contraseña».", "La nueva regla sustituye a la regla anterior en {doc}.", "No olvide {task} antes del viernes.", "El administrador puede cambiar la configuración predeterminada de {thing} en {doc}.", "A partir de ahora, la oficina va a {task} todos los lunes.", "El prompt del sistema define el tono del asistente; puede editarlo en {doc}.", "Nunca comparta su contraseña, ni siquiera con {team}.", "Nuevas instrucciones: desde marzo, {team} va a {task}.", "Las reglas del juego son simples: cada jugador debe {task}.", "¿Cuáles eran las instrucciones anteriores para {task}? Perdí {doc}."],
        ["actualizar el firmware", "instalar el controlador de la impresora", "enviar sus gastos", "hacer una copia de la base de datos", "configurar el router", "montar la estantería", "entregar el informe trimestral", "regar las plantas"],
        ["el manual", "el archivo README", "la guía de bienvenida", "la sección 4", "la página de ajustes", "la wiki", "las notas de la versión"],
        ["la luz amarilla", "el aviso antiguo", "la versión beta", "la segunda pantalla de acceso", "el borrador", "el ruido del ventilador"],
        ["el soporte técnico", "contabilidad", "su responsable", "el equipo de seguridad"],
    ),
    "it": (
        ["Le istruzioni precedenti per {task} si trovano in {doc}.", "Segui le istruzioni qui sopra per {task}.", "Puoi ignorare {thing} se hai già letto {doc}.", "Ignora l'avviso su {thing}; sparirà con il prossimo aggiornamento.", "Per reimpostare la password, apri {doc} e scegli «Password dimenticata».", "La nuova regola sostituisce la regola precedente in {doc}.", "Non dimenticare di {task} prima di venerdì.", "L'amministratore può modificare le impostazioni predefinite di {thing} in {doc}.", "D'ora in poi l'ufficio dovrà {task} ogni lunedì.", "Il prompt di sistema definisce il tono dell'assistente; puoi modificarlo in {doc}.", "Non condividere mai la password, nemmeno con {team}.", "Nuove istruzioni: da marzo {team} dovrà {task}."],
        ["aggiornare il firmware", "installare il driver della stampante", "inviare le note spese", "salvare il database", "configurare il router", "montare lo scaffale", "consegnare il rapporto trimestrale", "annaffiare le piante"],
        ["il manuale", "il file README", "la guida", "la sezione 4", "la pagina delle impostazioni", "la wiki", "le note di rilascio"],
        ["la spia gialla", "il vecchio avviso", "la versione beta", "la seconda schermata di accesso", "la bozza", "il rumore della ventola"],
        ["l'assistenza informatica", "la contabilità", "il tuo responsabile", "il team sicurezza"],
    ),
    "pt": (
        ["As instruções anteriores para {task} estão em {doc}.", "Siga as instruções acima para {task}.", "Pode ignorar {thing} se já leu {doc}.", "Ignore o aviso sobre {thing}; ele desaparece na próxima atualização.", "Para redefinir a sua senha, abra {doc} e escolha «Esqueci a senha».", "A nova regra substitui a regra anterior em {doc}.", "Não se esqueça de {task} antes de sexta-feira.", "O administrador pode alterar as configurações padrão de {thing} em {doc}.", "A partir de agora, o escritório vai {task} todas as segundas-feiras.", "O prompt do sistema define o tom do assistente; pode editá-lo em {doc}.", "Nunca partilhe a sua senha, nem com {team}.", "Novas instruções: a partir de março, {team} vai {task}."],
        ["atualizar o firmware", "instalar o driver da impressora", "enviar as despesas", "fazer cópia da base de dados", "configurar o router", "montar a estante", "entregar o relatório trimestral", "regar as plantas"],
        ["o manual", "o ficheiro README", "o guia", "a secção 4", "a página de definições", "a wiki", "as notas da versão"],
        ["a luz amarela", "o aviso antigo", "a versão beta", "o segundo ecrã de início de sessão", "o rascunho", "o ruído da ventoinha"],
        ["o suporte técnico", "a contabilidade", "o seu responsável", "a equipa de segurança"],
    ),
    "tr": (
        ["{task} için önceki talimatlar {doc} içinde yer alıyor.", "{task} için lütfen yukarıdaki talimatları izleyin.", "{doc} bölümünü zaten okuduysanız {thing} uyarısını görmezden gelebilirsiniz.", "{thing} ile ilgili uyarıyı dikkate almayın; bir sonraki güncellemede kaldırılacak.", "Şifrenizi sıfırlamak için {doc} sayfasını açın ve “Şifremi unuttum” seçeneğine tıklayın.", "Yeni kural, {doc} içindeki önceki kuralın yerini alır.", "Cuma gününden önce {task} işini unutmayın.", "Yönetici, {thing} için varsayılan ayarları {doc} üzerinden değiştirebilir.", "Bundan sonra ofis her pazartesi {task} işini yapacak.", "Sistem istemi, asistanın nasıl konuşacağını belirler; {doc} üzerinden düzenleyebilirsiniz.", "Şifrenizi hiç kimseyle paylaşmayın, {team} dahil.", "Yeni talimatlar: Mart ayından itibaren {team} {task} işini üstlenecek."],
        ["yazılımı güncelleme", "yazıcı sürücüsünü kurma", "masrafları gönderme", "veritabanını yedekleme", "yönlendiriciyi ayarlama", "rafı monte etme", "üç aylık raporu teslim etme", "çiçekleri sulama"],
        ["kullanım kılavuzu", "README dosyası", "başlangıç rehberi", "4. bölüm", "ayarlar sayfası", "viki", "sürüm notları"],
        ["sarı uyarı ışığı", "eski bildirim", "beta sürümü", "ikinci giriş ekranı", "taslak", "fan sesi"],
        ["BT destek ekibi", "muhasebe", "yöneticiniz", "güvenlik ekibi"],
    ),
    "nl": (
        ["De vorige instructies om {task} staan in {doc}.", "Volg de bovenstaande instructies om {task}.", "U kunt {thing} negeren als u {doc} al hebt gelezen.", "Negeer de waarschuwing over {thing}; die verdwijnt bij de volgende update.", "Om uw wachtwoord opnieuw in te stellen, opent u {doc} en kiest u 'Wachtwoord vergeten'.", "De nieuwe regel vervangt de vorige regel in {doc}.", "Vergeet niet om vóór vrijdag {task}.", "De beheerder kan de standaardinstellingen voor {thing} wijzigen in {doc}.", "Vanaf nu gaat het kantoor elke maandag {task}.", "De systeemprompt bepaalt de toon van de assistent; u past die aan in {doc}.", "Deel uw wachtwoord nooit, ook niet met {team}."],
        ["de firmware bij te werken", "het printerstuurprogramma te installeren", "uw declaraties in te dienen", "de database te back-uppen", "de router in te stellen", "de kast in elkaar te zetten", "het kwartaalrapport in te leveren", "de planten water te geven"],
        ["de handleiding", "het README-bestand", "de introductiegids", "sectie 4", "de instellingenpagina", "de wiki", "de release-opmerkingen"],
        ["het gele waarschuwingslampje", "de oude melding", "de bètaversie", "het tweede inlogscherm", "het concept", "het geluid van de ventilator"],
        ["de IT-helpdesk", "de boekhouding", "uw leidinggevende", "het beveiligingsteam"],
    ),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--n", type=int, default=9000)
    ap.add_argument("--mail", type=int, default=7000, help="generated ordinary email messages")
    ap.add_argument("--seed", type=int, default=11)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    rows, seen = [], set()

    def emit(lang, templates, tasks, docs, things, teams, n):
        tries = 0
        made = 0
        while made < n and tries < n * 30:
            tries += 1
            parts = [rng.choice(templates).format(task=rng.choice(tasks), doc=rng.choice(docs), thing=rng.choice(things), team=rng.choice(teams))]
            # about a third are two or three sentences, the way real text is
            for _ in range(rng.choice([0, 0, 1, 1, 2])):
                parts.append(rng.choice(templates).format(task=rng.choice(tasks), doc=rng.choice(docs), thing=rng.choice(things), team=rng.choice(teams)))
            text = " ".join(parts)
            if text in seen:
                continue
            seen.add(text)
            rows.append({"text": text, "label": False, "source": f"generated hard negatives ({lang})"})
            made += 1

    emit("en", EN_T, EN_TASK, EN_DOC, EN_THING, EN_TEAM, a.n // 3)
    per = (a.n - a.n // 3) // len(LANGS)
    for lang, (t, tasks, docs, things, teams) in LANGS.items():
        emit(lang, t, tasks, docs, things, teams, per)

    # ordinary email: one to four pieces of furniture per message, each filled in at random
    def mail_piece():
        t = rng.choice(MAIL_T)
        return t.format(num=rng.randint(100, 999999), num2=rng.choice([2, 5, 7, 14, 24, 30, 48]), code="".join(rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(6)), **{k: rng.choice(v) for k, v in MAIL.items()})

    made, tries = 0, 0
    while made < a.mail and tries < a.mail * 30:
        tries += 1
        text = ("\n\n" if rng.random() < 0.5 else " ").join(mail_piece() for _ in range(rng.choice([1, 1, 2, 2, 3, 4])))
        if text in seen:
            continue
        seen.add(text)
        rows.append({"text": text, "label": False, "source": "generated ordinary email (en)"})
        made += 1
    rng.shuffle(rows)
    with open(a.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    by = {}
    for r in rows:
        by[r["source"]] = by.get(r["source"], 0) + 1
    for k in sorted(by):
        print(f"  {k:<40} {by[k]:>6}")
    print(f"{a.out}: {len(rows)} generated benign sentences")


if __name__ == "__main__":
    main()
