from abc import ABC, abstractmethod
from .blockchain import Block # Импортируйте ваш класс Block
import random

class Consensus(ABC):
    @abstractmethod
    def validate_block(self, block: Block, chain: 'Blockchain') -> bool:
        """
        Валидирует блок в соответствии с правилами консенсуса.

        Args:
            block: Блок для валидации.
            chain: Экземпляр блокчейна (для доступа к предыдущим блокам и т.д.)

        Returns:
            True, если блок валиден, False иначе.
        """
        pass


class ProofOfWork(Consensus):
    def __init__(self, difficulty: int):
        self.difficulty = difficulty

    def validate_block(self, block: Block, chain: 'Blockchain') -> bool:
        """
        Валидирует блок, проверяя proof-of-work.
        """
        block_hash = block.compute_hash()
        return (block_hash.startswith('0' * self.difficulty) and
                chain.last_block.hash == block.previous_hash and  # Добавленная проверка
                block.previous_hash == chain.get_block_by_index(block.index-1).hash if block.index > 0 else True)



class ProofOfStake(Consensus):
    def __init__(self, validators: list[str]):
        self.validators = validators

    def validate_block(self, block: Block, chain: 'Blockchain') -> bool:
        """
        Упрощенная валидация Proof-of-Stake. 
        Выбирает случайного валидатора и проверяет, создал ли он блок.  
        В реальном PoS  логика значительно сложнее (учет стейка, 
        ротация валидаторов, slashing conditions и т.д.)
        """
        if not block.transactions: # Если нет транзакций
            return False

        creator = block.transactions[0].get('sender')  # Предполагаем, что первая транзакция - создание блока


        if creator not in self.validators:
            return False

        # Здесь должна быть более сложная логика проверки PoS
        # Например, проверка подписи, величины стейка,  и т.д.
        #  Этот пример -  сильно упрощенная  иллюстрация

        # Имитация проверки (замените на реальную логику)
        return random.random() < 0.8 # 80% шанс успешной валидации