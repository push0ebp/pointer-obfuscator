#pragma once

namespace PointerCipher
{
	constexpr char time[] = __TIME__;

	constexpr const long long seed = ((time[7] - '0') +
		(time[6] - '0') * 10 +
		(time[4] - '0') * 60 +
		(time[3] - '0') * 600 +
		(time[1] - '0') * 3600 +
		((time[0] - '0') * 36000) * 59243);
	constexpr inline int Rand(unsigned long long *seed)
	{
		return *seed = (*seed * 4317) % 0x6fffffff;
	}

	template <typename T>
	class Pointer
	{
	public:
		Pointer(const T p)
		{
			Init(p);
		}
		Pointer()
		{
		}
		~Pointer()
		{
			for (int i = 0; i < TABLE_LEN; i++)
			{
				if (i != get_idx())
				{
					delete ((long long*)((long long)tables_[i] ^ *keys_[TABLE_LEN - 1 - i]));
				}
			}
			for (int i = 0; i < TABLE_LEN; i++)
			{
				delete keys_[i];
			}
			delete keys_;
			delete tables_;
		}
		inline void Destroy()
		{
			delete get();
		}

		inline void Init(T p)
		{
			keys_ = new long long * [TABLE_LEN];
			tables_ = new long long *[TABLE_LEN];
			unsigned long long seed = PointerCipher::seed;
			for (int i = 0; i < TABLE_LEN; i++)
			{
				keys_[i] = new long long;
				*keys_[i] = PointerCipher::Rand(&seed) * 0x53849521995634 ^ get_xor_key();
			}
			for (int i = 0; i < TABLE_LEN; i++)
			{
				tables_[i] = (long long*)((long long)(new long long) ^ *keys_[TABLE_LEN - 1 - i]);
			}
			auto real_idx = get_idx();

			delete ((long long*)((long long)tables_[real_idx] ^ *keys_[TABLE_LEN - 1 - real_idx]));
			tables_[real_idx] = (long long *)((long long)p ^ *keys_[TABLE_LEN - 1 - real_idx]);
		}
		T get()
		{
			return reinterpret_cast<T>((long long)tables_[get_idx()] ^ *keys_[TABLE_LEN - 1 - get_idx()]);
		}
		inline long get_idx()
		{
			return (*keys_[KEY_TABLE_IDX] ^ XOR_KEY) * XOR_KEY % TABLE_LEN;
		}
		inline T set(const T v)
		{
			tables_[get_idx()] = (long long *)((long long)v ^ *keys_[TABLE_LEN - 1 - get_idx()]);
			return v;
		}

		constexpr inline long long get_xor_key()
		{
			return seed ^ 0x79056 << 10 ^ 0x11457 ^ seed << 24 ^ 0x44635 ^ seed << 32 ^ 0x79556 ^ seed << 40 ^ 0x68345;
		}
	private:
		enum : unsigned long long
		{
			TABLE_LEN = 256, XOR_KEY = 0x85438412847295 ^ PointerCipher::seed,
			KEY_TABLE_IDX = TABLE_LEN - 1
		};
		long long **tables_;
		long long **keys_;
	};

	template <typename T>
	class Array : public Pointer<T*>
	{
	public:
		Array(int size)
		{
			auto p = new T[size];
			Pointer<T*>::Init(p);
		}
		~Array()
		{
			delete Pointer<T*>::get();
		}
		inline T val(int idx, T v)
		{
			return Pointer<T*>::get()[idx] = v;
		}
		inline T val(int idx)
		{
			return Pointer<T*>::get()[idx];
		}
	};

	template <typename T>
	class Encrypted : public Pointer<T*>
	{
	public:
		Encrypted()
		{
			Init();
		}
		Encrypted(T t)
		{
			Init();
			val(t);
		}
		inline ~Encrypted()
		{
			delete Pointer<T*>::get();
		}
		inline void Init()
		{
			auto p = new T;
			Pointer<T*>::Init(p);
		}
		inline T val(T v)
		{
			return *Pointer<T*>::get() = v;
		}
		inline T val()
		{
			return *Pointer<T*>::get();
		}
	private:
	};

	inline void rc4(char *enc, char *dec, unsigned int enc_size, char *key, unsigned int key_size)
	{
		for (int i = 0; i < enc_size; i++)
			dec[i] = enc[i];
		auto _key = Array<int>(key_size / sizeof(int));
		for (int i = 0; i < key_size; i++)
			*(char*)((char*)_key.get() + i) = key[i];
		for (int i = 0; i < enc_size / sizeof(int); i++)
		{
			int k = (0x12583943 - (i ^ 43));
			if (i % 2)
				k = ~k;
			unsigned int idx = i % (key_size / sizeof(int));
			_key.get()[idx] ^= k;
			*(int*)((int*)dec + i) ^= _key.get()[idx];
		};
	}

}


