<?php

// LDAPAuth.class.php

// *************************************************************************
// *                                                                       *
// * (c) 2008-2011 Wolf Software Limited <info@wolf-software.com>          *
// * All Rights Reserved.                                                  *
// *                                                                       *
// * This program is free software: you can redistribute it and/or modify  *
// * it under the terms of the GNU General Public License as published by  *
// * the Free Software Foundation, either version 3 of the License, or     *
// * (at your option) any later version.                                   *
// *                                                                       *
// * This program is distributed in the hope that it will be useful,       *
// * but WITHOUT ANY WARRANTY; without even the implied warranty of        *
// * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
// * GNU General Public License for more details.                          *
// *                                                                       *
// * You should have received a copy of the GNU General Public License     *
// * along with this program.  If not, see <http://www.gnu.org/licenses/>. *
// *                                                                       *
// *************************************************************************

class LDAPAuth
{
  private $class_name        = "LDAPAuth";
  private $class_version     = "1.0.0";
  private $class_author      = "Wolf Software";
  private $class_source      = "http://www.wolf-software.com/Downloads/ldapauth_class";

  protected $_account_suffix     = "@cantv.com.ve";
  protected $_base_dn            = "";
  protected $_user_dn            = "";
  protected $_domain_controllers = array();
  protected $_use_ssl            = false;
  protected $_use_tls            = false;
  protected $_use_ad             = false;

  protected $_conn;
  protected $_bind;

  public function class_name()
    {
      return $this->class_name;
    }

  public function class_version()
    {
      return $this->class_version;
    }

  public function class_author()
    {
      return $this->class_author;
    }

  public function class_source()
    {
      return $this->class_source;
    }

  public function __construct($options = array())
    {
      if (!function_exists('ldap_connect'))
        {
          echo 'No LDAP support for PHP.  See: http://www.php.net/ldap';
          exit;
        }

      if (count($options) > 0)
        {
          if (array_key_exists("account_suffix", $options))
            {
              $this->_account_suffix = $options["account_suffix"];
            }
          if (array_key_exists("user_dn", $options))
            {
              $this->_user_dn = $options["user_dn"];
            }
          if (array_key_exists("base_dn", $options))
            {
              $this->_base_dn = $options["base_dn"];
            }
          if (array_key_exists("domain_controllers", $options))
            {
              $this->_domain_controllers = $options["domain_controllers"];
            }
          if (array_key_exists("use_ssl", $options))
            {
              $this->_use_ssl = $options["use_ssl"];
            }
          if (array_key_exists("use_tls", $options))
            {
              $this->_use_tls = $options["use_tls"];
            }
          if (array_key_exists("use_ad", $options))
            {
              $this->_use_ad = $options["use_ad"];
            }
        }
      return $this->connect();
    }

  public function __destruct()
    {
      $this->close();
    }

  public function connect()
    {
      $dc = $this->random_controller();

      if ($this->_use_ssl)
        {
          $this->_conn = ldap_connect("ldaps://".$dc, 636);
        }
      else
        {
          $this->_conn = ldap_connect($dc);
        }

      ldap_set_option($this->_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
      ldap_set_option($this->_conn, LDAP_OPT_REFERRALS, 0);

      if ($this->_use_tls)
        {
          ldap_start_tls($this->_conn);
        }
      if ($this->_base_dn == NULL)
        {
          $this->_base_dn = $this->find_base_dn();
        }
      return (true);
    }

  public function close()
    {
      ldap_close($this->_conn);
    }

  public function authenticate($username, $password)
    {
      if (($username === NULL) || ($password === NULL) || empty($username) || empty($password))
        {
          return false;
        }
      $ret = true;

      if ($this->_use_ad)
        {
          $user_string = $username . $this->_account_suffix;
        }
      else
        {
          $user_string = "UID=" . $username . "," . $this->_user_dn;
        }
      $this->_bind = @ldap_bind($this->_conn, $user_string, $password);
      if (!$this->_bind)
        {
          $ret = false;
        }
      return $ret;
    }

  public function last_error()
    {
      return ldap_error($this->_conn);
    }

  protected function random_controller()
    {
      mt_srand(doubleval(microtime()) * 100000000);
      return ($this->_domain_controllers[array_rand($this->_domain_controllers)]);
    }

  protected function find_base_dn()
    {
      $namingContext = $this->get_root_dse(array('defaultnamingcontext'));
      return ($namingContext[0]['defaultnamingcontext'][0]);
    }

  protected function get_root_dse($attributes = array("*", "+"))
    {
      if (!$this->_bind)
        {
          return (false);
        }
      $sr = @ldap_read($this->_conn, NULL, 'objectClass=*', $attributes);
      $entries = @ldap_get_entries($this->_conn, $sr);
      return $entries;
    }
}

?>
