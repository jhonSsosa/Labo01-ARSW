/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

/**
 *
 * @author hcadavid
 */
public class HostBlackListsValidator {

    private static final int BLACK_LIST_ALARM_COUNT=5;

    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     * @param ipaddress suspicious host's IP address.
     * @return  Blacklists numbers where the given host's IP address was found.
     */
    public List<Integer> checkHost(String ipaddress, int numHilos){
        LinkedList<Integer> blackListOcurrences=new LinkedList<>();
        int ocurrencesCount=0;
        List<HostBlackListsThreats> hilos = new ArrayList<>();
        HostBlacklistsDataSourceFacade skds=HostBlacklistsDataSourceFacade.getInstance();

        int checkedListsCount=0;
        int extra = 0;

        int range = skds.getRegisteredServersCount()/numHilos;
        int mod = skds.getRegisteredServersCount()%numHilos;

        for(int i =0;i<numHilos;i++) {
            int ini = range*i;
            int fin = range*(i+1);
            HostBlackListsThreats busqueda = new HostBlackListsThreats(ipaddress,ini,fin);
            hilos.add(busqueda);
            busqueda.start();
            extra = fin;
        }
        if(mod != 0){
            HostBlackListsThreats busqueda = new HostBlackListsThreats(ipaddress,extra,extra+mod);
            hilos.add(busqueda);
            busqueda.start();
        }
        for (HostBlackListsThreats hilo : hilos) {
            try {
                hilo.join();
                ocurrencesCount += hilo.getOcurrencias();
                checkedListsCount += hilo.getChequeoListasNegras();
                blackListOcurrences.addAll(hilo.getListaOcurrencias());
            }catch (Exception e){
                e.printStackTrace();
            }
        }

        if (ocurrencesCount>=BLACK_LIST_ALARM_COUNT){
            skds.reportAsNotTrustworthy(ipaddress);
        }
        else{
            skds.reportAsTrustworthy(ipaddress);
        }                
        
        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}", new Object[]{checkedListsCount, skds.getRegisteredServersCount()});
        
        return blackListOcurrences;
    }
    
    
    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());
    


}
