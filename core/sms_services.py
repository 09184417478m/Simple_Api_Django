from abc import ABC, abstractmethod
import environ
import os


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env = environ.Env()
env_file = os.path.join(BASE_DIR, '.env')
environ.Env.read_env(env_file)



class SmsService(ABC):
    name = ""
    is_active = ""

    @abstractmethod
    def send_sms(self, phone: str, message: str) -> None:
        pass

class IrancellSmsService(SmsService):
    name = env('irancell_name')
    is_active = env('is_active_irancell')

    def send_sms(self, phone: str, message: str) -> None:
        print(f"{self.name}: Sending SMS to {phone}: {message}")

class RightelSmsService(SmsService):
    name = env('rightel_name')
    is_active = env('is_active_rightel')

    def send_sms(self, phone: str, message: str) -> None:
        print(f"{self.name}: Sending SMS to {phone}: {message}")

class HamrahAvvalSmsService(SmsService):
    name = env('hamrah_name')
    is_active = env('is_active_hamrahavval')

    def send_sms(self, phone: str, message: str) -> None:
        print(f"{self.name}: Sending SMS to {phone}: {message}")

class SmsServiceFactory:
    @staticmethod
    def get_sms_service() -> SmsService:
        for cls in SmsService.__subclasses__():
            if cls.is_active == 'true':
                return cls()
        raise ValueError("No active SMS service available")
