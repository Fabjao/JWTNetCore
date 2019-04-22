using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using jwtCore.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace jwtCore.Controllers
{

  [Route("api/[controller]")]
  public class TokenController : Controller
  {

    private readonly IConfiguration _configuration;

    public TokenController(IConfiguration Configuration)
    {
      _configuration = Configuration;
    }

    [AllowAnonymous]
    [HttpPost]
    public IActionResult Post([FromBody] Usuario usuario)
    {
      if (usuario.Nome == "Fabio" && usuario.Senha == "123456")
      {
        var criacaoClaims = new[]{
            new Claim(ClaimTypes.Name, usuario.Nome),
            new Claim(ClaimTypes.Role, "Admin") //Para definir perfil
        };


        //recebe uma instancia da classe SymmetricSecurityKey
        //armazenando a chave de criptogradia usada na criação do token
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["SecurityKey"]));

        //recebe um objeto do tipo SigninCredentials contendo a chave de 
        //criptogradia e o algoritmo de segurança empregados na geração
        //de assinaturas digitais para tokens
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
          issuer: "fabio.com",
          audience: "fabio.com",
          expires: DateTime.Now.AddMinutes(5),
          claims: criacaoClaims,
          signingCredentials: creds
        );
        return Ok(new
        {
          token = new JwtSecurityTokenHandler().WriteToken(token)
        });
      }
      return BadRequest("Credenciais invalidas....");
    }
  }
}