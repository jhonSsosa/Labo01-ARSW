package edu.eci.arsw.blacklistvalidator;

import java.util.LinkedList;
import java.util.List;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

public class HostBlackListsThreats extends Thread {

    private int occurrencias;
    private int contadorListas;
    private String ip;
    private int inicio;
    private int fin;
    private LinkedList<Integer> ListaOcurrencias;

    public HostBlackListsThreats(String ip, int inicio, int fin){
        this.ip = ip;
        this.inicio = inicio;
        this.fin = fin;
        this.occurrencias = 0;
        ListaOcurrencias = new LinkedList<>();
    }

    public void run() {
        this.chequeo(ip, inicio, fin);
    }

    public void chequeo(String ip, int inicio, int fin){
        HostBlacklistsDataSourceFacade skds= HostBlacklistsDataSourceFacade.getInstance();
        for (int i = inicio; i < fin; i++){
            contadorListas++;

            if (skds.isInBlackListServer(i, ip)){
                
                ListaOcurrencias.add(i);
                
                occurrencias++;
            }
        }
    }

    public List<Integer> getListaOcurrencias(){
        return ListaOcurrencias;
    }

    public int getOcurrencias(){
        return occurrencias;
    }

    public int getChequeoListasNegras(){
        return contadorListas;
    }
}