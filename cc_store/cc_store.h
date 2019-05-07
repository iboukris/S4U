#include <string>

class cc_store
{
    std::string m_ccache;
    std::string m_principal;
    std::string m_password;
    std::string m_impersonate_kt;

    cc_store(const std::string& ccache,
             const std::string& principal,
             const std::string& password,
             const std::string& impersonate_kt);

    bool init();
    bool verify(const std::string& target);

public:
    static bool init_creds(const std::string& ccache,
                           const std::string& principal,
                           const std::string& password,
                           const std::string& target = "");

    static bool impersonate_creds(const std::string& ccache,
                                  const std::string& principal,
                                  const std::string& impersonate_kt,
                                  const std::string& target = "");
};
