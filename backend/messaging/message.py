from dataclasses import dataclass

@dataclass
class Message:
    sender: str  # Адрес отправителя (публичный ключ?)
    recipient: str # Адрес получателя (публичный ключ?)
    content: str # Содержание сообщения (зашифрованное)
    timestamp: float # Временная метка
    signature: str # Цифровая подпись (опционально, но рекомендуется)

    def to_dict(self): # Для сериализации
        return self.__dict__

    @staticmethod
    def from_dict(data): # Для десериализации
        return Message(**data)