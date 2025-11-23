import secrets
import re
from datetime import datetime, timedelta
from typing import List, Tuple

def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)

def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
    """
    Valida la forza della password e restituisce (success, lista_errori)
    
    Requisiti:
    - Minimo 8 caratteri
    - Almeno 1 lettera maiuscola
    - Almeno 1 lettera minuscola  
    - Almeno 1 numero
    - Almeno 1 carattere speciale (@$!%*?&)
    - Massimo 128 caratteri
    - Non deve contenere spazi
    - Non deve essere una password comune
    """
    errors = []
    
    if len(password) < 8:
        errors.append("La password deve avere almeno 8 caratteri")
    
    if len(password) > 128:
        errors.append("La password non può superare 128 caratteri")
    
    if not re.search(r"[A-Z]", password):
        errors.append("La password deve contenere almeno una lettera maiuscola")
    
    if not re.search(r"[a-z]", password):
        errors.append("La password deve contenere almeno una lettera minuscola")
    
    if not re.search(r"[0-9]", password):
        errors.append("La password deve contenere almeno un numero")
    
    if not re.search(r"[@$!%*?&]", password):
        errors.append("La password deve contenere almeno un carattere speciale (@$!%*?&)")
    
    if re.search(r"\s", password):
        errors.append("La password non può contenere spazi")
    
    # Check password comuni (lista ridotta per esempio)
    common_passwords = {
        "password", "12345678", "qwerty", "admin", "welcome", 
        "password1", "123456789", "00000000", "aaaaaaaa"
    }
    if password.lower() in common_passwords:
        errors.append("La password è troppo comune e insicura")
    
    # Check sequenze semplici
    if re.search(r"(.)\1{3,}", password):  # 4+ caratteri identici consecutivi
        errors.append("La password contiene troppi caratteri identici consecutivi")
    
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|7890)", password):
        errors.append("La password contiene sequenze numeriche troppo semplici")
    
    return len(errors) == 0, errors

# Funzione helper per validazione semplice (solo booleano)
def is_password_strong(password: str) -> bool:
    """Versione semplificata che restituisce solo True/False"""
    is_valid, _ = validate_password_strength(password)
    return is_valid

# Funzione per generare suggerimenti password
def generate_password_suggestions() -> List[str]:
    """Genera alcune idee per password robuste"""
    return [
        "Usa una frase facile da ricordare ma difficile da indovinare",
        "Combina parole non correlate con numeri e simboli",
        "Esempio: Cane@Rosa_2024! oppure Mare#Giallo_987?",
        "Inizia con una maiuscola, aggiungi simboli e numeri alla fine",
        "Evita informazioni personali come nome o data di nascita"
    ]