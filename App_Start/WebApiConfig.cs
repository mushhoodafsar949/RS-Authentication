using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;
using System.Web.Http.Cors;
using RS_Authentication_Server.App_Start;
using Unity;

namespace RS_Authentication_Server
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services

            // Web API routes
            string origin = "*";
            EnableCorsAttribute cors = new EnableCorsAttribute(origin, "*", "*");
            config.EnableCors(cors);
           var container = new UnityContainer();
            //container.RegisterType<SP_authorization_Result, UserAuthService>();
           config.DependencyResolver = new UnityResolver(container);
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{action}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }
    }
}
