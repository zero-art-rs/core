import time
from collections import defaultdict

load('./ibbe_del7.sage')
load('./fs_ibbe_del7.sage')

def time_measurement_ibbe_del7(number_of_users: int, repeat: int=10):
    summary_time_start = time.time()
    
    ibbe = IBBE_Del7()

    time_table = {
        "Setup": 0,
        "Extract": 0,
        "Encrypt": 0,
        "Decrypt": 0,
    }

    ID = 0
    S = [i for i in range(number_of_users)]

    for _ in range(repeat):
        time_start = time.time()
        msk, pk = ibbe.Setup(number_of_users=number_of_users)
        time_finish = time.time()
        time_table["Setup"] += time_finish - time_start

        time_start = time.time()
        sk_ID = ibbe.Extract(msk=msk, ID=ID)
        time_finish = time.time()
        time_table["Extract"] += time_finish - time_start

        time_start = time.time()
        Hdr, K = ibbe.Encrypt(S=S, pk=pk)
        time_finish = time.time()
        time_table["Encrypt"] += time_finish - time_start

        time_start = time.time()
        K_ = ibbe.Decrypt(S=S, ID=ID, sk_ID=sk_ID, Hdr=Hdr, pk=pk)
        time_finish = time.time()
        time_table["Decrypt"] += time_finish - time_start

    summary_time_finish = time.time()

    print(f"--- Evaluation: {number_of_users} users, repeat {repeat} times ---")
    print(f"Avarage Setup time: {time_table["Setup"] / repeat:0.3f} s.")
    print(f"Avarage Extract time: {time_table["Extract"] / repeat:0.3f} s.")
    print(f"Avarage Encrypt time: {time_table["Encrypt"] / repeat:0.3f} s.")
    print(f"Avarage Decrypt time: {time_table["Decrypt"] / repeat:0.3f} s.")
    print(f"Test time: {(summary_time_finish - summary_time_start):0.3f} s.")

def time_measurement_in_general_ibbe_del7(): # example
    number_of_users = 1
    step = 10
    for _ in range(3):
        number_of_users *= step
        time_measurement_ibbe_del7(number_of_users=number_of_users)

def time_measurement_fs_ibbe_del7(number_of_users: int, repeat: int=10):
    summary_time_start = time.time()
    
    ibbe = FS_IBBE_Del7()

    time_table = defaultdict(int)

    S = [i for i in range(number_of_users)]
    ID = 0

    for _ in range(repeat):
        time_start = time.time()
        msk, pk = ibbe.Setup(number_of_users=number_of_users)
        time_finish = time.time()
        time_table["Setup"] += time_finish - time_start

        time_start = time.time()
        presk_ID = ibbe.Extract(msk=msk, ID=ID)
        time_finish = time.time()
        time_table["Extract"] += time_finish - time_start

        time_start = time.time()
        sk = ibbe.KeyGen(r=ibbe.randint(), pk=pk, presk_ID=presk_ID)
        time_finish = time.time()
        time_table["KeyGen"] += time_finish - time_start

        time_start = time.time()
        Hdr, K = ibbe.Encrypt(S=S, pk=pk)
        time_finish = time.time()
        time_table["Encrypt"] += time_finish - time_start

        time_start = time.time()
        K_ = ibbe.Decrypt(S=S, ID=ID, sk=sk, Hdr=Hdr, pk=pk)
        time_finish = time.time()
        time_table["Decrypt"] += time_finish - time_start

        time_start = time.time()
        sk = ibbe.KeyUpdate(pk=pk, r_new=ibbe.randint(), sk=sk)
        time_finish = time.time()
        time_table["KeyUpdate"] += time_finish - time_start

    summary_time_finish = time.time()

    print(f"--- Evaluation: {number_of_users} users, repeat {repeat} times ---")
    print(f"Test time: {(summary_time_finish - summary_time_start):0.3f} s.")
    for key in time_table:
        print(f"Avarage {key} time: {time_table[key] / repeat:0.3f} s.")

def time_measurement_in_general_fs_ibbe_del7(): # example
    number_of_users = 1
    step = 10
    for _ in range(3):
        number_of_users *= step
        time_measurement_fs_ibbe_del7(number_of_users=number_of_users)

time_measurement_in_general_fs_ibbe_del7()