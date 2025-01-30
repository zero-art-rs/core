load('./ag_enc_id.sage')

def time_evalation(m: int, repeat: int=10):
    summary_time_start = time.time()
    time_table = {
        "Setup": 0,
        "Extract": 0,
        "Encrypt": 0,
        "Decrypt": 0,
    }

    ID = 0
    S = [i for i in range(m)]

    for _ in range(repeat):
        time_start = time.time()
        msk, pk, pairing = Setup(l=None, m=m)
        time_finish = time.time()
        time_table["Setup"] += time_finish - time_start

        time_start = time.time()
        sk_ID = Extract(msk=msk, ID=ID, pairing=pairing)
        time_finish = time.time()
        time_table["Extract"] += time_finish - time_start

        time_start = time.time()
        Hdr, K = Encrypt(S, pk, pairing)
        time_finish = time.time()
        time_table["Encrypt"] += time_finish - time_start

        time_start = time.time()
        K_ = Decrypt(S=S, ID=ID, sk_ID=sk_ID, Hdr=Hdr, pk=pk, pairing=pairing)
        time_finish = time.time()
        time_table["Decrypt"] += time_finish - time_start

    summary_time_finish = time.time()

    # print(f"--- Evaluation for {m} users as avarage of {repeat} tests ---")
    print(f"--- Evaluation: {m} users, repeat {repeat} times ---")
    print(f"Setup time: {time_table["Setup"] / repeat:0.3f} s.")
    print(f"Extract time: {time_table["Extract"] / repeat:0.3f} s.")
    print(f"Encrypt time: {time_table["Encrypt"] / repeat:0.3f} s.")
    print(f"Decrypt time: {time_table["Decrypt"] / repeat:0.3f} s.")
    print(f"Test time: {(summary_time_finish - summary_time_start):0.3f} s.")
    print("")

if __name__ == "__main__":
    size = 1
    step = 10
    for m in range(6):
        size *= step
        time_evalation(m=size, repeat=1)