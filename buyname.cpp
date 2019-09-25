#include <vector>
#include <ctype.h>
#include <cstring>
#include <algorithm>
#include <cmath>
#include <eosiolib/eosio.hpp>
#include <eosiolib/asset.hpp>
#include <eosiolib/types.hpp>
#include <eosiolib/action.hpp>
#include <eosiolib/symbol.hpp>
#include <eosiolib/crypto.h>
#include <eosiolib/transaction.hpp>

#define CORE_TOKEN S(4, EOS)
#define CORE_ACCOUNT N(shadowbanker) // eosio.token //shadowbanker
#define TEAM_STAKE N(buyname.io)
#define TEAM_SERVICE N(shadowserver) //eosbuynameio // shadowserver

using namespace std;
using namespace eosio;

class signup : public contract {

  public:

    const string nameSuffix=".e";
    const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const int8_t mapBase58[256] = {
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
            -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
            22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
            -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
            47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    };

    struct signup_public_key {
        uint8_t        type;
        array<unsigned char,33> data;
    };
    struct permission_level_weight {
        permission_level permission;
        weight_type weight;
    };
    struct key_weight {
        signup_public_key key;
        weight_type weight;
    };
    struct wait_weight {
        uint32_t wait_sec;
        weight_type weight;
    };
    struct authority {
        uint32_t threshold;
        vector<key_weight> keys;
        vector<permission_level_weight> accounts;
        vector<wait_weight> waits;
    };
    struct newaccount {
        account_name creator;
        account_name name;
        authority owner;
        authority active;
    };

    signup(account_name self):contract(self),
    rammarkets(N(eosio), N(eosio)),
    settings(_self, _self),
    prices(_self, _self),
    users(_self, _self)
    {
      initialize();
    }

    void transfer(account_name from, account_name to, asset quantity, string memo ) 
    {
        require_auth( from ); 

        if(quantity.is_valid() && quantity.symbol == CORE_TOKEN && quantity.amount > 0 && from != _self && to == _self && from!=N(eosio.ram))
        {
            auto settingitr = settings.begin();
            eosio_assert( settingitr != settings.end(), "系统尚未初始化" );
            eosio_assert( settingitr->is_pause==0, "系统维护，请稍后再来" ); 
            if(quantity.amount==settingitr->make_referrer_fee)
            {
                auto useritr = users.find(from);
                eosio_assert(useritr==users.end(), "此账号已经是推荐人");
                auto code = name_to_code((name{from}.to_string()));
                auto number = stoull(code);
                auto codeidx = users.template get_index<N(code)>();
                auto codeitr = codeidx.find(number);
                eosio_assert(codeitr == codeidx.end(), "推荐码已被使用");
                users.emplace(_self,[&](auto & s){
                    s.owner = from;
                    s.code = number;
                    s.is_special = 0;
                    s.is_disable=0;
                    s.water_ratio = 0;
                    s.bonus_ratio = 0;
                });
                settings.modify(settingitr, 0, [&](auto &s) {
                    s.user_count +=1;
                });
                
                string remark = "您的推荐码是：";
                remark.append(code);
                remark.append("，请务必提醒您的客户注册时在备注填写推荐码，成功注册后您和他将收到分红和返利，如不填则没有。备注填写：*****.e+公钥+");
                remark.append(code);
                remark.append("。您还可设置客户返利，详情buyname.io");
                asset referrerfee(1,CORE_TOKEN);
                action(
                permission_level{ _self, N(active) },
                CORE_ACCOUNT, N(transfer),
                std::make_tuple(_self,from, referrerfee, remark)
                ).send();
                
            }else if(quantity.amount==1 && from==TEAM_SERVICE)
            {
                auto separator = memo.find('+');
                eosio_assert(separator != string::npos, "备注缺少+号分隔符");
                memo.erase(std::remove_if(memo.begin(),memo.end(),[](unsigned char x) { return std::isspace(x); }),memo.end());
                size_t pos;
                string data;
                pos = sub2sep(memo, &data, '+', 0, true);
                eosio_assert(!data.empty(), "备注缺少账号");
                eosio_assert(data.size()<=12, "无效的EOS账号");
                account_name account = string_to_name(data.c_str());
                data = memo.substr(++pos);
                eosio_assert(!data.empty(), "备注缺少分红比例");
                eosio_assert(is_digits(data), "分红必须是数字");
                auto bonus_ratio = stoull(data);
                eosio_assert(bonus_ratio<=100, "分红比例不能超过100%");
                auto useritr = users.find(account);
                if(useritr==users.end())
                {
                    auto code = name_to_code((name{account}.to_string()));
                    auto number = stoull(code);
                    auto codeidx = users.template get_index<N(code)>();
                    auto codeitr = codeidx.find(number);
                    eosio_assert(codeitr == codeidx.end(), "推荐码已被使用");
                    
                    users.emplace(_self,[&](auto & s){
                        s.owner = account;
                        s.code = number;
                        s.is_special = 1;
                        s.is_disable=0;
                        s.water_ratio = 0;
                        s.bonus_ratio = bonus_ratio*100;
                    });

                    settings.modify(settingitr, 0, [&](auto &s) {
                        s.user_count +=1;
                    });

                    string remark = "您的推荐码是：";
                    remark.append(code);
                    remark.append("，请务必提醒您的客户注册时在备注填写推荐码，成功注册后您和他将收到分红和返利，如不填则没有。备注填写：*****.e+公钥+");
                    remark.append(code);
                    remark.append("。您还可设置客户返利，详情buyname.io");
                    asset referrerfee(1,CORE_TOKEN);
                    action(
                    permission_level{ _self, N(active) },
                    CORE_ACCOUNT, N(transfer),
                    std::make_tuple(_self,account, referrerfee, remark)
                    ).send();

                }else{
                    users.modify(useritr, 0, [&](auto &s) {
                        s.water_ratio = (bonus_ratio==0?0:useritr->water_ratio);
                        s.bonus_ratio = bonus_ratio*100;
                    });
                }
            }else
            {
                auto separator = memo.find('+');
                auto addcount = count(memo.begin(),memo.end(),'+');
                eosio_assert(separator != string::npos, "备注缺少+号分隔符");
                memo.erase(std::remove_if(memo.begin(),memo.end(),[](unsigned char x) { return std::isspace(x); }),memo.end());
                size_t pos;
                string data;
                pos = sub2sep(memo, &data, '+', 0, true);
                eosio_assert(!data.empty(), "备注缺少账号");
                eosio_assert(data.size()<=12, "无效的EOS账号");
                eosio_assert(data.size()>=7, "1-4位暂未开放注册");
                auto prefix = data.substr(0, data.size()-2);
                auto priceitr = prices.find(prefix.size());
                eosio_assert(priceitr!=prices.end(), "账号定价不存在");
                eosio_assert(quantity.amount== priceitr->amount, "转账金额不符合标准");
                //eosio_assert(data.substr(data.size()-2,2)==nameSuffix, "账号必须是以.e结尾");   
                account_name account = string_to_name(data.c_str());
                eosio_assert(!is_account(account), "此账号已经被注册");
                if(addcount==2)
                {
                    pos = sub2sep(memo, &data, '+', ++pos, true);
                }else
                {
                    data = memo.substr(++pos);
                }
                eosio_assert(!data.empty(), "备注缺少公钥");
                eosio_assert(data.size()==53, "公钥长度不正确");
                auto key = data;
                string pubkey_prefix("EOS");
                auto result = mismatch(pubkey_prefix.begin(), pubkey_prefix.end(), key.begin());
                eosio_assert(result.first == pubkey_prefix.end(), "公钥缺少EOS前缀");
                auto base58substr = key.substr(pubkey_prefix.length());
                vector<unsigned char> vch;
                eosio_assert(decode_base58(base58substr, vch), "反编码公钥失败");
                eosio_assert(vch.size() == 37, "公钥长度不正确");
                array<unsigned char,33> pubkey_data;
                copy_n(vch.begin(), 33, pubkey_data.begin());
                checksum160 check_pubkey;
                ripemd160(reinterpret_cast<char *>(pubkey_data.data()), 33, &check_pubkey);
                eosio_assert(memcmp(&check_pubkey.hash, &vch.end()[-4], 4) == 0, "输入了无效的公钥");
                asset stake_net(settingitr->stake_net, CORE_TOKEN);
                asset stake_cpu(settingitr->stake_cpu, CORE_TOKEN);
                asset stake_ram(getRamPrice(3.00), CORE_TOKEN);
                auto cost = stake_ram.amount+settingitr->stake_net + settingitr->stake_cpu;
                eosio_assert(quantity.amount>cost && (quantity.amount - cost)>priceitr->minimum, "利润低于系统最低值0.1 EOS"); 
                auto amount = quantity.amount - cost;
                auto bonus_fee = 0UL;
                auto water_fee = 0UL;
                auto team_fee = amount;
                auto is_referrer_buy = false;
                account_name referrer;
                data = memo.substr(++pos);
                if(addcount==2 && !data.empty())
                {
                    eosio_assert(is_digits(data), "推荐码必须是数字");
                    auto code = stoull(data);
                    auto useridx = users.template get_index<N(code)>();
                    auto useritr = useridx.find(code);
                    eosio_assert(useritr != useridx.end(), "推荐码不存在");
                    auto water_ratio = double(useritr->water_ratio)/double(10000);
                    auto bonus_ratio = double(useritr->bonus_ratio)/double(10000);
                    eosio_assert(water_ratio<=10, "退水比例超出限制");
                    eosio_assert(bonus_ratio<=100, "分红比例超出限制");
                    is_referrer_buy = true;
                    referrer = useritr->owner;
                    water_fee = water_ratio*double(amount);
                    auto pure_profit = amount - water_fee;
                    if(useritr->is_special==1)
                    {
                        bonus_fee = bonus_ratio*pure_profit;
                    }else
                    {
                        bonus_fee = double(settingitr->referrer_fee)/double(10000)*pure_profit;
                    }
                    team_fee = pure_profit - bonus_fee;

                    useridx.modify(useritr, 0, [&](auto &s) {
                        s.profit += bonus_fee;
                        s.count +=1;
                    });
                }
                settings.modify(settingitr, 0, [&](auto &s) {
                    s.sell_count +=1;
                });
                signup_public_key pubkey = {
                    .type = 0,
                    .data = pubkey_data,
                };
                key_weight pubkey_weight = {
                    .key = pubkey,
                    .weight = 1,
                };
                authority owner = authority{
                    .threshold = 1,
                    .keys = {pubkey_weight},
                    .accounts = {},
                    .waits = {}
                };
                authority active = authority{
                    .threshold = 1,
                    .keys = {pubkey_weight},
                    .accounts = {},
                    .waits = {}
                };
                newaccount new_account = newaccount{
                    .creator = _self,
                    .name = account,
                    .owner = owner,
                    .active = active
                };

                action(
                        permission_level{ _self, N(active) },
                        N(eosio),
                        N(newaccount),
                        new_account
                ).send();

                action(
                        permission_level{ _self, N(active)},
                        N(eosio),
                        N(buyram),
                        make_tuple(_self, account, stake_ram)
                ).send();

                if(settingitr->stake_cpu>0 && settingitr->stake_net>0)
                {
                    action(
                            permission_level{ _self, N(active)},
                            N(eosio),
                            N(delegatebw),
                            make_tuple(_self, account, stake_net, stake_cpu, true)
                    ).send();
                }
                if(bonus_fee>0)
                {
                    asset bonusfee(bonus_fee,CORE_TOKEN);
                    transaction bonus; 
                    bonus.actions.emplace_back(permission_level{_self, N(active)}, CORE_ACCOUNT, N(transfer), std::make_tuple(_self,referrer, bonusfee, std::string("祝万事顺遂！"))); 
                    bonus.delay_sec = 1; 
                    bonus.send(next_id(), _self, false); 
                }
                if(water_fee>0)
                {
                    asset waterfee(water_fee,CORE_TOKEN);
                    transaction water; 
                    water.actions.emplace_back(permission_level{_self, N(active)}, CORE_ACCOUNT, N(transfer), std::make_tuple(_self,from, waterfee, std::string("欢迎注册eos的e，喜得靓号，祝万事顺遂！"))); 
                    water.delay_sec = 1; 
                    water.send(next_id(), _self, false); 
                }
                if(!is_referrer_buy)
                {
                    asset notifyfee(1,CORE_TOKEN);
                    transaction notify1; 
                    notify1.actions.emplace_back(permission_level{_self, N(active)}, CORE_ACCOUNT, N(transfer), std::make_tuple(_self,from, notifyfee, std::string("成为超级短号推荐人，大笔eos天天赚！每个短号最多可获50%利润分红。详情登陆buyname.io"))); 
                    notify1.delay_sec = 1; 
                    notify1.send(next_id(), _self, false); 

                    transaction notify2; 
                    notify2.actions.emplace_back(permission_level{_self, N(active)}, CORE_ACCOUNT, N(transfer), std::make_tuple(_self,account, notifyfee, std::string("成为超级短号推荐人，大笔eos天天赚！每个短号最多可获50%利润分红。详情登陆buyname.io"))); 
                    notify2.delay_sec = 1; 
                    notify2.send(next_id(), _self, false); 
                }
            }
        }
    }
    
    //@abi action
    void test()
    {

    }

    //@abi action
    void clean(const account_name from,uint64_t clean_type)
    {
      require_auth( from ); 
      eosio_assert( from==TEAM_SERVICE, "你没有权限执行此操作");

      if(clean_type==1)//设置
      {
        auto settingitr = settings.begin();
        while(settingitr != settings.end()) {settingitr = settings.erase(settingitr);}  
      }else if(clean_type==2)//价格
      {
        auto priceitr = prices.begin();
        auto pricecounter = 0;
        while( priceitr != prices.end() ) {
          if(pricecounter>=200)break;
          priceitr = prices.erase(priceitr);
          pricecounter++;
        }
      }else if(clean_type==3)//账号
      {
        auto useritr = users.begin();
        auto usercounter = 0;
        while( useritr != users.end() ) {
          if(usercounter>=200)break;
          useritr = users.erase(useritr);
          usercounter++;
        }
      }
    }

    void initialize()
    {
        auto settingitr = settings.begin();
        if(settingitr==settings.end())
        {
            settings.emplace(_self,[&](auto & s){
                s.id = 0;
                s.is_pause = 0;              // 暂停购买
                s.stake_cpu = 0;             // 抵押CPU
                s.stake_net = 0;             // 抵押NET            
                s.stake_ram = 4096;          // 抵押RAM
                s.stake_max = 10000;         // 抵押最大金额
                s.user_count = 0;            // 总用户数
                s.sell_count = 0;            // 总销售数
                s.team_fee = 7500;           // 系统比例
                s.water_fee = 1000;          // 退水比例
                s.referrer_fee = 2500;       // 推荐人比例
                s.make_referrer_fee = 1230;  // 创建推荐人费用
            });   
        }

        // 5位 .X 6.7EOS, 6位 .X 5.7EOS, 7位 .X 4.7EOS 
        // 8位 .X 3.7EOS, 9位 .X 2.7EOS, 10位 .X 1.7EOS
        auto priceitr = prices.begin();
        if(priceitr==prices.end())
        {
            prices.emplace(_self,[&](auto & s){s.length = 5;s.amount = 57000;s.minimum = 1000;});
            prices.emplace(_self,[&](auto & s){s.length = 6;s.amount = 47000;s.minimum = 1000;});
            prices.emplace(_self,[&](auto & s){s.length = 7;s.amount = 37000;s.minimum = 1000;});
            prices.emplace(_self,[&](auto & s){s.length = 8;s.amount = 27000;s.minimum = 1000;});
            prices.emplace(_self,[&](auto & s){s.length = 9;s.amount = 17000;s.minimum = 1000;});
            prices.emplace(_self,[&](auto & s){s.length = 10;s.amount = 8000;s.minimum = 1000;});
        }
    }

    bool is_digits(const std::string &str)
    {
        return std::all_of(str.begin(), str.end(), ::isdigit); 
    }

    string name_to_code(string text)
    {
        size_t number = 0;
        checksum256 hashcode;
        sha256(const_cast<char*>(text.c_str()), text.size() * sizeof(char), &hashcode);
        string codehex = to_hex((char*)hashcode.hash, sizeof(hashcode.hash));
        hash_combine(number, codehex);
        uint64_t whole = now()+number;
        string code = to_string(whole);
        return code.substr(code.size()-6,6);
    }

    template <class T>inline void hash_combine(std::size_t& seed, const T& v) {
        std::hash<T> hasher;
        seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    }

    string to_hex(const char* d, uint32_t s) {
        std::string r;
        const char* to_hex = "0123456789abcdef";
        uint8_t* c = (uint8_t*)d;
        for (uint32_t i = 0; i < s; ++i)
            (r += to_hex[(c[i] >> 4)]) += to_hex[(c[i] & 0x0f)];
        return r;
    }

    uint64_t next_id(){
        auto settingitr = settings.begin();
        settings.modify(settingitr, 0, [&](auto &s) {
            s.transaction_id++;
        });
        return settingitr->transaction_id;
    }

    uint64_t getRamPrice(double bytes){
        auto ramitr = rammarkets.find(S(4,RAMCORE));
        eosio_assert(ramitr != rammarkets.end(), "内存购买失败");
        auto price = (( 1.0 * ramitr->quote.balance.amount / 10000 ) / ( 1.0 + ramitr->base.balance.amount / 1024.0 )) * bytes * 10000;
        return price;
    }

    size_t sub2sep(const string& input,string* output,const char& separator,const size_t& first_pos = 0,const bool& required = false) {
        eosio_assert(first_pos != string::npos, "解析备注信息失败");
        auto pos = input.find(separator, first_pos);
        if (pos == string::npos) {
            eosio_assert(!required, "解析备注信息错误");
            return string::npos;
        }
        *output = input.substr(first_pos, pos - first_pos);
        return pos;
    }

    bool DecodeBase58(const char* psz, std::vector<unsigned char>& vch)
    {
        while (*psz && isspace(*psz))
            psz++;
        int zeroes = 0;
        int length = 0;
        while (*psz == '1') {
            zeroes++;
            psz++;
        }
        int size = strlen(psz) * 733 /1000 + 1; 
        std::vector<unsigned char> b256(size);
        static_assert(sizeof(mapBase58)/sizeof(mapBase58[0]) == 256, "mapBase58.size() should be 256"); 
        while (*psz && !isspace(*psz)) {
            int carry = mapBase58[(uint8_t)*psz];
            if (carry == -1) 
                return false;
            int i = 0;
            for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
                carry += 58 * (*it);
                *it = carry % 256;
                carry /= 256;
            }
            assert(carry == 0);
            length = i;
            psz++;
        }
        while (isspace(*psz))
            psz++;
        if (*psz != 0)
            return false;
        std::vector<unsigned char>::iterator it = b256.begin() + (size - length);
        while (it != b256.end() && *it == 0)
            it++;
        vch.reserve(zeroes + (b256.end() - it));
        vch.assign(zeroes, 0x00);
        while (it != b256.end())
            vch.push_back(*(it++));
        return true;
    }

    bool decode_base58(const string& str, vector<unsigned char>& vch) {
        return DecodeBase58(str.c_str(), vch);
    }

  private:

    // @abi table settings i64
    struct setting{
      uint64_t id;                  // id
      uint64_t is_pause;            // 暂停购买
      uint64_t stake_cpu;           // 抵押CPU
      uint64_t stake_net;           // 抵押NET
      uint64_t stake_ram;           // 抵押RAM
      uint64_t stake_max;           // 抵押最大金额
      uint64_t user_count;          // 总用户数
      uint64_t sell_count;          // 总销售数
      uint64_t team_fee;            // 系统比例
      uint64_t water_fee;           // 退水比例
      uint64_t referrer_fee;        // 推荐人比例
      uint64_t make_referrer_fee;   // 成为推荐人费用
      uint64_t transaction_id;      // 延迟转账

      uint64_t primary_key() const { return id; }
      EOSLIB_SERIALIZE(setting, (id)(is_pause)(stake_cpu)(stake_net)(stake_ram)(stake_max)(user_count)(sell_count)(team_fee)(water_fee)(referrer_fee)(make_referrer_fee)(transaction_id))
    };
    typedef multi_index<N(settings), setting> _setting;
    _setting settings;

    // @abi table prices i64
    struct price {
      uint64_t length;              // 账号长度
      uint64_t amount;              // 账号价格
      uint64_t minimum;             // 账号除去成本、退水、分红后的最低价

      uint64_t primary_key() const { return length; }

      EOSLIB_SERIALIZE(price, (length)(amount)(minimum))
    };
    typedef multi_index<N(prices), price> _price;
    _price prices;
    
    // @abi table users i64
    struct user {
      account_name owner;           // 账号
      uint64_t code;                // 推荐代码
      uint64_t count;               // 销售数量
      uint64_t profit;              // 推荐利润
      uint64_t is_special;          // 是否特权推荐人
      uint64_t is_disable;          // 是否已禁用
      uint64_t water_ratio;         // 退水比例
      uint64_t bonus_ratio;         // 分红比例

      account_name primary_key() const { return owner; }
      uint64_t get_code_key() const { return code; }
      uint64_t get_profit_key() const { return profit; }

      EOSLIB_SERIALIZE(user, (owner)(code)(count)(profit)(is_special)(is_disable)(water_ratio)(bonus_ratio))
    };
    typedef multi_index<N(users), user,
        indexed_by<N(code), const_mem_fun<user, uint64_t, &user::get_code_key>>,
        indexed_by<N(profit), const_mem_fun<user, uint64_t, &user::get_profit_key>>
    > _user;
    _user users;

    struct exchange_state {
      asset    supply;

      struct connector {
         asset balance;
         double weight = .5;

         EOSLIB_SERIALIZE( connector, (balance)(weight) )
      };

      connector base;
      connector quote;

      uint64_t primary_key()const { return supply.symbol; }

      EOSLIB_SERIALIZE( exchange_state, (supply)(base)(quote) )
   };
   typedef eosio::multi_index<N(rammarket), exchange_state> rammarket;
    rammarket rammarkets;

};

 #define EOSIO_ABI_EX( TYPE, MEMBERS ) \
 extern "C" { \
    void apply( uint64_t receiver, uint64_t code, uint64_t action ) { \
       if( action == N(onerror)) { \
          eosio_assert(code == N(eosio), "onerror action's are only valid from the \"eosio\" system account"); \
       } \
       auto self = receiver; \
       if((code == CORE_ACCOUNT && action == N(transfer)) || (code == self && (action == N(clean) || action == N(test) || action == N(onerror))) ) { \
          TYPE thiscontract( self ); \
          switch( action ) { \
             EOSIO_API( TYPE, MEMBERS ) \
          } \
       } \
    } \
 }

EOSIO_ABI_EX(signup, (transfer)(clean)(test))


